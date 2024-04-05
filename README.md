- sig_overwrite_sp.c
  Overwrite ss_sp, ss_size directly from sigframe during signal handler from userspace.

Below demo how sigaltstack can be nested, hence why restore_altstack is needed inside rt_sigreturn.
- sigaltstack_from_sighandler.c
  Call sigaltstack inside signal handler
- sigaltstack_twice_from_sighandler.c
  Calling sigaltstack inside signal hanlder and where altstack is in use by the sighandler.
  Note: in order for this to be successful, the altstack must be created with SS_AUTODISARM.
  
