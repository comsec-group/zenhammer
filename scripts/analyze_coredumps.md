# Debugging coredumps using gdb

```
gdb <executable_path> <coredump_file_path>
(gdb) where
(gdb) bt full
```

# Test: Generating a coredump in the same folder

```
sleep 10 &
killall -SIGSEGV sleep

```

# Activating coredumps

```
ulimit -c unlimited
sysctl kernel.core_pattern
```

