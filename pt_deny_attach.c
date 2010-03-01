/*
 * pt_deny_attach.c
 *
 * Author: Landon J. Fuller <landonf@opendarwin.org>
 * This software is placed in the public domain
 * 
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <mach/mach_types.h>
#include <sys/systm.h>
#include <sys/kernel.h>

#include <stdint.h>
#include "structures.h"

static struct sysent *_sysent;
extern int nsysent;

typedef int	ptrace_func_t (struct proc *, struct ptrace_args *, int *);
static ptrace_func_t *real_ptrace;

static int our_ptrace (struct proc *p, struct ptrace_args *uap, int *retval)
{
	
	if (uap->req == PT_DENY_ATTACH) {
		printf("[ptrace] Blocking PT_DENY_ATTACH for pid %d.\n", uap->pid);
		return (0);
	} else {
		return real_ptrace(p, uap, retval);
	}
}

/*
 * nsysent is placed directly before the hidden sysent, so skip ahead
 * and sanity check that we've found the sysent array.
 *
 * Clearly, this is extremely fragile and not for general consumption.
 */
static struct sysent *find_sysent () {
	unsigned int table_size;
	struct sysent *table;

	table_size = sizeof(struct sysent) * nsysent;
	table = (struct sysent *) ( ((char *) &nsysent) + sizeof(nsysent) );

#if __i386__
	/* For reasons unknown, the table is offset by an additional 28 bytes on my i386 system */
	table = (struct sysent *) ( ((uint8_t *) table) + 28);
#endif

	printf("[ptrace] Found nsysent at %p (count %d), calculated sysent location %p.\n", &nsysent, nsysent, table);

	/* Sanity check */
	printf("[ptrace] Sanity check %d %d %d %d %d %d: ",
		table[SYS_syscall].sy_narg,
		table[SYS_exit].sy_narg,
		table[SYS_fork].sy_narg,
		table[SYS_read].sy_narg,
		table[SYS_wait4].sy_narg,
		table[SYS_ptrace].sy_narg);

	if (table[SYS_syscall].sy_narg == 0 &&
		table[SYS_exit].sy_narg == 1  &&
		table[SYS_fork].sy_narg == 0 &&
		table[SYS_read].sy_narg == 3 &&
		table[SYS_wait4].sy_narg == 4 &&
		table[SYS_ptrace].sy_narg == 4)
	{
		printf("sysent sanity check succeeded.\n");
		return table;
	} else {
		printf("sanity check failed, could not find sysent table.\n");
		return NULL;
	}
}

kern_return_t pt_deny_attach_start (kmod_info_t *ki, void *d) {
	_sysent = find_sysent();
	if (_sysent == NULL) {
		return KERN_FAILURE;
	}

	real_ptrace = (ptrace_func_t *) _sysent[SYS_ptrace].sy_call;
	_sysent[SYS_ptrace].sy_call = (sy_call_t *) our_ptrace;
	printf("[ptrace] Patching ptrace(PT_DENY_ATTACH, ...).\n");
    return KERN_SUCCESS;
}


kern_return_t pt_deny_attach_stop (kmod_info_t * ki, void * d) {
	_sysent[SYS_ptrace].sy_call = (sy_call_t *) real_ptrace;
	printf("[ptrace] Unpatching ptrace(PT_DENY_ATTACH, ...)\n");
    return KERN_SUCCESS;
}
