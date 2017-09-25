#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

/* mach */
#include <mach/mach.h>
#include <mach/mach_error.h>
#include <mach/thread_act.h>
#include <mach/mach_vm.h>
#include <servers/bootstrap.h>

static mach_port_t server_mach_port;

