fsveil
================================================================================
fsveil runs programs with a "veiled view" of the filesystem.  It uses linux
namespaces to create a private sysroot and doesn't require root privileges.

fsveil takes a list of files/directories to keep in the new sysroot:

```
fsveil FILES/DIRS -- CMD...
```

You can also specify that some directories be mounted with options like this:
```
fsveil --start-mount-opt nosuid,noexec /sys /proc /tmp --end-mount-opt ...
```

Checkout [zig-fsveil](zig-fsveil) for an example script that will run the zig
compiler with minimal access to the filesystem.

### Build

Build tested with zig version 0.11.0
