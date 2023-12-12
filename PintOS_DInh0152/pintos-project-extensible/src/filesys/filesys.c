#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "threads/thread.h"

/* Partition that contains the file system. */
struct block *fs_device;

static void do_format (void);

static char *dirname(char *path);
static char *basename(char *path);
static bool rel_to_abs(const char *file_path, struct inode **inode);
static bool is_parent_dir(struct inode *child, struct inode *parent);

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void
filesys_init (bool format)
{
  fs_device = block_get_role (BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC ("No file system device found, can't initialize file system.");

  inode_init ();
  free_map_init ();

  /* Initialize the buffer cache */
  filesys_cache_init();

  if (format)
    do_format ();

  struct inode *root_node = inode_open(ROOT_DIR_SECTOR);
  thread_current()->working_dir = dir_open(root_node);

  free_map_open ();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void
filesys_done (void)
{
  /* Flush the buffer cache */
  cache_flush();
  free_map_close ();
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool
filesys_create (const char *name, off_t initial_size, bool is_dir)
{

  block_sector_t inode_sector = 0;
  char base_name[NAME_MAX + 1];
  struct inode *dir_inode = NULL;
  struct dir *dir = NULL;

  struct inode *cur_inode = NULL;
  bool relative = rel_to_abs(name, &cur_inode);
  if (relative) {
    if (inode_removed(dir_get_inode(thread_current()->working_dir))) {
      /* Disallow create() on relative directories if working directory inode was removed */
      return false;
    }
  }

  dir = try_get_dir(name, base_name);
  
  bool success = (dir != NULL
                  && free_map_allocate (1, &inode_sector)
                  && inode_create (inode_sector, initial_size, is_dir)
                  && dir_add (dir, base_name, inode_sector));
  if (!success && inode_sector != 0)
    free_map_release (inode_sector, 1);

  dir_close (dir);

  return success;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file *
filesys_open (const char *name)
{
  if (strcmp(name, "") == 0) {
    return NULL;
  }

  char file_name[NAME_MAX + 1];
  struct dir *dir = dir_open_root();
  struct inode *inode = NULL;

  if (strcmp(name, "/") == 0) {
    struct file *root_file = file_open(dir_get_inode(dir));
    dir_close(dir);
    return root_file;
  } else if (strcmp(name, ".") == 0) {
    if (inode_removed(dir_get_inode(thread_current()->working_dir))) {
      /* Disallow open(..) if working directory inode was removed */
      return NULL;
    }
    struct file *working_dir = file_open(dir_get_inode(dir_reopen(thread_current()->working_dir)));
    dir_close(dir);
    return working_dir;
  }

  char *base_name = basename(name);

  bool exists = false;

  if (dir == NULL || !dir_lookup(dir, base_name, &inode)) {
	  dir = try_get_dir(name, file_name);
	  if (dir != NULL) {
		  exists = dir_lookup(dir, file_name, &inode);
    } else {
      return NULL;
    }
  }
  dir_close(dir);

  free(base_name);

  return file_open(inode);
}

/* Extracts a file name part from *SRCP into PART, and updates *SRCP so that the
   next call will return the next file name part. Returns 1 if successful, 0 at
   end of string, -1 for a too-long file name part.
   Function is given in project 3 spec. */
static int
get_next_part(char part[NAME_MAX + 1], const char **srcp) {
	const char *src = *srcp;
	char *dst = part;

	/* Skip leading slashes. If it's all slashes, we're done. */
	while (*src == '/')
		src++;
	if (*src == '\0')
		return 0;

	/* Copy up to NAME_MAX chars from SRC to DST. Add null terminator. */
	while (*src != '/' && *src != '\0') {
		if (dst < part + NAME_MAX)
			*dst++ = *src;
		else
			return -1;
		src++;
	}
	*dst = '\0';

	/* Advance source pointer. */
	*srcp = src;
	return 1;
}

bool
filesys_chdir(const char *syscall_arg)
{

  if (strcmp(syscall_arg, "..") == 0) {

    struct inode *working_dir_inode = dir_get_inode(thread_current()->working_dir);
    
    thread_current()->working_dir = dir_open(
                                      inode_open(
                                        inode_get_parent(
                                          dir_get_inode(
                                            thread_current()->working_dir))));

    dir_close(dir_reopen(thread_current()->working_dir));

    return true;
  }

	char base_name[NAME_MAX + 1];
	struct dir *dir = try_get_dir(syscall_arg, base_name);
	struct inode *dir_inode = NULL;

	if (dir_lookup(dir, base_name, &dir_inode)) {
		dir_close(thread_current()->working_dir);
		thread_current()->working_dir = dir_open(dir_inode);
		return true;
	}
	return false;
}

/* dirname */
static char *dirname(char *path)
{
  char *path_copy = malloc(strlen(path) + 1);
  strlcpy(path_copy, path, sizeof(char) * (strlen(path) + 1));

  int i;

  if(path_copy == NULL || path_copy[0] == '\0')
    return "/";
  for(i = strlen(path_copy) - 1; i >= 0 && path_copy[i] == '/'; i--);
  if(i == -1)
    return path_copy;
  for(i--; i >= 0 && path_copy[i] != '/'; i--);
  if(i == -1)
    return ".";
  path_copy[i] = '\0';
  for(i--; i >= 0 && path_copy[i] == '/'; i--);
  if(i == -1)
    return "/";
  path_copy[i+1] = '\0';
  
  return path_copy;
}

/* basename */
static char *basename(char *path)
{

  char *path_copy = malloc(strlen(path) + 1);
  strlcpy(path_copy, path, sizeof(char) * (strlen(path) + 1));

  int i;

  if(path_copy == NULL || path_copy[0] == '\0')
    return "";
  for(i = strlen(path_copy) - 1; i >= 0 && path_copy[i] == '/'; i--);
  if(i == -1)
    return "/";
  for(path_copy[i+1] = '\0'; i >= 0 && path_copy[i] != '/'; i--);

  char *base_name = malloc(strlen(&path_copy[i+1]) + 1);
  strlcpy(base_name, &path_copy[i+1], sizeof(char) * (strlen(&path_copy[i+1]) + 1));

  free(path_copy);

  return base_name;
}

/* Attempt to find the directory where the file exists.
   Return dir if it exists, else return NULL.
   Saves base filename in file_path or sets to "." if path is a directory. */
struct dir *
try_get_dir(const char *file_path, char next_part[NAME_MAX + 1]) {

	if (strcmp(file_path, "\0") == 0)
		return NULL;
	
  char *directory = dirname(file_path);

  struct inode *cur_inode = NULL;
  bool relative = rel_to_abs(file_path, &cur_inode);
  struct inode *next_inode = NULL;

  if (cur_inode == NULL) {
    return NULL;
  }

  if (strcmp(directory, ".") == 0) {
    strlcpy(next_part, file_path, sizeof(char) * (strlen(file_path) + 1));
  } else {
    
    int i = 0;

    while (get_next_part(next_part, &directory) > 0 && cur_inode != NULL)
    {
      struct dir *cur_dir = dir_open(cur_inode);
      /* Commenting out inode_close seemed to fix a lot of issues.  Maybe because the 
         path is being passed into try_get_dir (instead of directory) so the while runs
         for one too many iterations and closes the dir we need, then hits the break on
         the else so uwe try to call dir_open on a closed inode? */
      
      if (dir_lookup(cur_dir, next_part, &next_inode)) {
        dir_close(cur_dir);

        if (next_inode != NULL && inode_is_dir(next_inode)) {
          cur_inode = next_inode;
        }
      }
      
      else if (get_next_part(next_part, &directory) != 0) {
        return NULL;
      }
      else
        break;
      i++;
    }
  }

  char *base_name = basename(file_path);  

  strlcpy(next_part, base_name, sizeof(char) * (strlen(base_name) + 1));

  /* Probably should free these strings somehow, but not here (it causes errors) */
  //free(directory);
  free(base_name);

	return dir_open(cur_inode);
}

/* Get the correct directory inode according to the given file_path. */

bool rel_to_abs(const char *file_path, struct inode **inode)
{
	if (file_path[0] == '/') {
		*inode = dir_get_inode(dir_open_root());
    return false;
  }

  if (thread_current()->working_dir != NULL) {
	  *inode = dir_get_inode(dir_reopen(thread_current()->working_dir));
  } else {
    *inode = NULL;
  }
  return true;
}

/* Checks if PARENT is a parent directory of CHILD.  Returns true if
it is, false otherwise */
static bool is_parent_dir(struct inode *child, struct inode *parent)
{
  if (parent == NULL || child == NULL) {
    return false;
  }

  struct inode *curr_inode = inode_open(inode_get_parent(child));

  return inode_get_inumber(curr_inode) == inode_get_inumber(parent);
}


/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool
filesys_remove (const char *name)
{
  if (strcmp(name, "/") == 0) {
    /* You can't remove root directory */
    return false;
  }

  char base_name[NAME_MAX + 1];
  struct dir *dir = NULL;

  dir = try_get_dir(name, base_name);


  struct inode *dir_inode = NULL;
  dir_lookup(dir, base_name, &dir_inode);

  if (inode_is_dir(dir_inode) && 
    !(inode_get_inumber(dir_inode) == inode_get_inumber(dir_get_inode(thread_current()->working_dir))) &&
    is_parent_dir(dir_get_inode(thread_current()->working_dir), dir_inode)) {
    /* Disallow removal of directory that is parent of working directory 
    (but allow removal of current working directory) */
    return false;
  }

  bool success = dir != NULL && dir_remove (dir, base_name);
  dir_close (dir);

  return success;
}

/* Formats the file system. */
static void
do_format (void)
{
  printf ("Formatting file system...");
  free_map_create ();
  if (!dir_create (ROOT_DIR_SECTOR, 16))
    PANIC ("root directory creation failed");
  free_map_close ();
  printf ("done.\n");
}
