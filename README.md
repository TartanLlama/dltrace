# dltrace
A demonstration of tracing dynamic library loading and unloading on Linux.

### Background

- The dynamic linker mainains a rendezvous structure, which helps the debugger trace what libraries have been loaded or unloaded.
- This structure is stored where the  `.dynamic` section of the ELF file is loaded from the executable.
- It maintains a linked list of shared library descriptors, along with a pointer to a function which is called whenever the linked list is updated.
- The rendezvous structure is initialized before the execution of the program begins.

### Algorithm
- The tracer looks up the entry point of the program in the ELF header (or it could use the auxillary vector stored in `/proc/<pid>/aux`)
- The tracer places a breakpoint on the entry point of the program and begins execution.
- When the breakpoint is hit, the address of the rendezvous structure is found by looking up the load address of `.dynamic` in the ELF file.
- The rendezvous structure is examined to get the list of currently loaded libraries.
- A breakpoint is set on the linker update function.
- Whenever the breakpoint is hit, the list is updated.
- The tracer infinitely loops, continuing the program and waiting for a signal until the tracee signals that it has exited.
