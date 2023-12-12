#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);
static void fill_stack(char *argv[], size_t argc, struct intr_frame *esp);
static struct wait_status *try_get_wait_st(tid_t child_tid);

/* exec_info is data structure to be created in process_execute(...)
   and passed to start_process to track loading of new process.
*/
struct exec_info {
  char *file_name;                 /* Filename of program that will be loaded */
  struct semaphore load_sema;      /* Init to 0, down in parent calling exec, up in child after load */
  struct wait_status *wait_status; /* Wait status for child */
  bool success;                    /* Whether or not load was successful */
  struct thread *parent;           /* Parent thread struct */
};

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name)
{
  char *fn_copy;
  tid_t tid;

  struct exec_info exec_inf;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, file_name, PGSIZE);

  /* Make space for storing file_name that will be used to
     name the thread. */
  size_t len = (strcspn(file_name, " ") + 1) * sizeof(char);
  char *thread_name = malloc(len);
  /* Make a copy of the file_name only. */
  strlcpy(thread_name, file_name, len);

  /* Init members of exec_info */
  exec_inf.file_name = fn_copy;
  exec_inf.parent = thread_current();
  sema_init (&exec_inf.load_sema, 0);

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create (thread_name, PRI_DEFAULT, start_process, &exec_inf);

  if (tid == TID_ERROR) {
    palloc_free_page (fn_copy);
  } else {
    /* Wait for child to finish loading */
    sema_down(&(exec_inf.load_sema));

    /* Child is finished loading */
    if (!exec_inf.success) {
      /* Error on load */
      tid = TID_ERROR;
      palloc_free_page (fn_copy);
    } else {
      /* Successful load, add thread to children list */
      list_push_back(&thread_current()->children, &exec_inf.wait_status->elem);
    }
  }

  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *exec_inf_)
{
  struct exec_info *exec_inf = exec_inf_;

  char *file_name = exec_inf->file_name;
  struct intr_frame if_;
  bool success;

  /* Make a duplicate of filename for argc counting */
  char file_name_dup[strlen(file_name) + 1];
  strlcpy(file_name_dup, file_name, strlen(file_name) + 1);
  /* Make strtok pointer for argc counting */
  char *strtok_ptr_count;
  char *token_count = strtok_r(file_name_dup, " ", &strtok_ptr_count);
  /* Init argc to 0 */
  size_t argc = 0;
  /* Iterate through copy of input string to count argc */
  while (token_count != NULL)
  {
    token_count = strtok_r(NULL, " ", &strtok_ptr_count);
    /* New word, increment argc */
    argc++;
  }
  /* Init argv array of char pointers */
  char *argv[argc + 1];
  /* Make strtok pointer for filling argv */
  char *strtok_ptr;
  /* Start tokenizing file name */
  char *token = strtok_r(file_name, " ", &strtok_ptr);

  /* Fill argv with split words */
  int i = 0;
  while (token != NULL)
  {
    /* Copy token address to appropriate argv index */
    argv[i] = token;
    /* Move to next token */
    token = strtok_r(NULL, " ", &strtok_ptr);
    /* Increment index */
    i++;
  }

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (file_name, &if_.eip, &if_.esp);

  bool complete_success = success;

  if (success) {
    /* Push arguments to stack */
    fill_stack(argv, argc, &if_);

    /* Set wait_status of exec_info */
    thread_current()->wait_st = malloc(sizeof(*exec_inf->wait_status));
    exec_inf->wait_status = thread_current()->wait_st;

    bool malloc_success = exec_inf->wait_status != NULL;
    /* Check if malloc was successful */
    if (malloc_success) {
      /* Set the members of wait_status we created */
      exec_inf->wait_status->ref_count = 2;
      exec_inf->wait_status->child_tid = thread_current()->tid;
	    exec_inf->wait_status->exit_code = -1;
      sema_init (&(exec_inf->wait_status->sema), 0);
      lock_init (&(exec_inf->wait_status->lock));
	    list_push_back(&thread_current()->children, &exec_inf->wait_status->elem);
    }

    palloc_free_page(file_name);

    /* Set success flag */
    complete_success = complete_success && malloc_success;

    if (complete_success) {
      if (exec_inf->parent == NULL || exec_inf->parent->working_dir == NULL) {
        thread_current()->working_dir = dir_open_root();
      } else {
        thread_current()->working_dir = dir_reopen(exec_inf->parent->working_dir);
      }
    }
  }
  /* Set member success flag of exec_info */
  exec_inf->success = complete_success;
  /* Done loading, wake up parent */
  sema_up (&exec_inf->load_sema);

  /* Exit thread if we didn't load successfully */
  if (!complete_success) {
    thread_exit ();
  }

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

void
fill_stack(char *argv[], size_t argc, struct intr_frame *if_) {
  /* Fake return address is 0 */
  size_t fake_ra = 0;
  /* Initialize char array of argument addresses
     (addresses in char array exist on user stack) */
  char *arg_addrs[argc + 1];

  /* Init index and arg_size vars for pushing to user stack */
  int index;
  size_t arg_size;
  /* Push words to top of stack frame */
  for (index = 0; index < argc; index++) {
    /* Get the length of current word */
    arg_size = strlen((char*)argv[index]) + 1;
    /* Decrement user stack pointer accordingly */
    if_->esp -= arg_size;
    /* Add the current stack pointer (address of current word) to argument adresses */
    arg_addrs[index] = (char *) if_->esp;
    /* Copy word to user stack from argv */
    memcpy(if_->esp, argv[index], arg_size);
  }

  /* Push NULL pointer sentinel (according to 3.1.9 in spec) */
  arg_addrs[argc] = NULL;

  /* Push argv char pointers (right to left order) */
  size_t arg_addrs_size = (argc + 1) * sizeof(char *);
  if_->esp -= (size_t) (if_->esp) % 4 + arg_addrs_size;
  memcpy (if_->esp, arg_addrs, arg_addrs_size);

  /* Push argv */
  if_->esp -= 4;
  *((char ***) (if_->esp)) = if_->esp + 4;

  /* Push argc */
  if_->esp -= 4;
  *((int *) (if_->esp)) = argc;

  /* Push fake return address */
  if_->esp -= 4;
  memcpy(if_->esp, &fake_ra, 4);
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid)
{
	//sema_down(&temporary);
	//return 0;
	int exit_code = -1;
	struct wait_status *child_wait_st = try_get_wait_st(child_tid);

	if (child_wait_st == NULL) {
		return exit_code;
	}

	sema_down(&child_wait_st->sema);
	list_remove(&child_wait_st->elem);
	exit_code = child_wait_st->exit_code;
	return exit_code;
}

struct wait_status*
try_get_wait_st(tid_t child_tid) {
	struct thread *cur_thread = thread_current();
	struct list_elem *cur_child = list_begin(&cur_thread->children);
	struct list_elem *last_child = list_end(&cur_thread->children);

	while (cur_child != last_child) {
		struct wait_status *child_wait_st = list_entry(cur_child, struct wait_status, elem);
		cur_child = list_next(cur_child);
		if (child_wait_st->child_tid == child_tid) {
			return child_wait_st;
		}
	}
	return NULL;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;

  /* Close the running file. */
  file_close(cur->exec_file);

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL)
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }

  /* Set exit code and up wait_status sema */
  if (cur->wait_st != NULL) {

    //cur->wait_st->exit_code = cur->exit_code;
	printf("%s: exit(%d)\n", &cur->name, cur->wait_st->exit_code);
    sema_up (&cur->wait_st->sema);

    int ref_count;

    lock_acquire (&cur->wait_st->lock);
    cur->wait_st->ref_count -= 1;
    ref_count = cur->wait_st->ref_count;
    lock_release (&cur->wait_st->lock);

    /*if (ref_count == 0) {
      free(cur->wait_st);
    }*/
  }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp)
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL)
    goto done;
  process_activate ();

  /* Open executable file. */
  file = filesys_open (file_name);
  if (file == NULL)
    {
      printf ("load: %s: open failed\n", file_name);
      goto done;
    }

  /* Deny writes from other threads. */
  file_deny_write(file);

  /* Assign current running file in thread. */
  t->exec_file = file;

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024)
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done;
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++)
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type)
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file))
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  // file_close (t->exec_file);
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file)
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
    return false;

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file))
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz)
    return false;

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;

  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0)
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Get a page of memory. */
      uint8_t *kpage = palloc_get_page (PAL_USER);
      if (kpage == NULL)
        return false;

      /* Load this page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          palloc_free_page (kpage);
          return false;
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      if (!install_page (upage, kpage, writable))
        {
          palloc_free_page (kpage);
          return false;
        }

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp)
{
  uint8_t *kpage;
  bool success = false;

  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL)
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success)
        *esp = PHYS_BASE;
      else
        palloc_free_page (kpage);
    }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}
