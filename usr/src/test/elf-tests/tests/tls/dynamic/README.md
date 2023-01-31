Test that dynamic TLS (that is, TLS for modules loader after execution)
functions to a basic degree.

This is basically the same as the `static/` tests, the info for which is
repeated below, but we build a generic wrapper and `dlopen(3C)` our tests into
it.

Build an application specifying all 4 TLS models for a pair of variables one
in `.tdata` one in `.tbss`, at execution time check their value on the main
thread, and change it.  Then spawn threads which each check they get the
initial value and then mutate that value.  When all threads have mutated, go
back again and check each thread still has unique values.
