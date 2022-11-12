/*-
 * Copyright (c) 2004 David Schultz <das@FreeBSD.ORG>
 * Copyright (c) 2013 Andrew Turner <andrew@FreeBSD.ORG>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD: head/lib/msun/aarch64/fenv.c 280913 2015-03-31 19:07:28Z andrew $
 */

#include <fenv.h>
#include <stdint.h>
#include <sys/controlregs.h>

/*
 * Rounding modes
 *
 * We can't just use the hardware bit values here, because that would
 * make FE_UPWARD and FE_DOWNWARD negative, which is not allowed.
 */
#define	_ROUND_MASK	(FE_TONEAREST | FE_DOWNWARD | \
			 FE_UPWARD | FE_TOWARDZERO)
#define	_ROUND_SHIFT	22

/* Default floating-point environment */
extern const fenv_t	__fe_dfl_env;

/* We need to be able to map status flag positions to mask flag positions */
#define _FPUSW_SHIFT	8
#define	_ENABLE_MASK	(FE_ALL_EXCEPT << _FPUSW_SHIFT)

int
feclearexcept(int __excepts)
{
	uint32_t fpsr = read_fpsr();
	fpsr &= ~(__excepts & FE_ALL_EXCEPT);
	write_fpsr(fpsr);
	return (0);
}

int
fegetexceptflag(fexcept_t *__flagp, int __excepts)
{
	uint32_t fpsr = read_fpsr();
	*__flagp = (fpsr & (__excepts & FE_ALL_EXCEPT));
	return (0);
}

int
fesetexceptflag(const fexcept_t *__flagp, int __excepts)
{
	uint32_t fpsr = read_fpsr();
	fpsr &= ~(__excepts & FE_ALL_EXCEPT);
	fpsr |= (*__flagp & (__excepts & FE_ALL_EXCEPT));
	write_fpsr(fpsr);
	return (0);
}

int
feraiseexcept(int __excepts)
{
	uint32_t fpsr = read_fpsr();
	fpsr |= (__excepts & FE_ALL_EXCEPT);
	write_fpsr(fpsr);
	return (0);
}

int
fetestexcept(int __excepts)
{
	uint32_t fpsr = read_fpsr();
	return (fpsr & (__excepts & FE_ALL_EXCEPT));
}

int
fegetround(void)
{
	uint32_t fpcr = read_fpcr();
	return ((fpcr & _ROUND_MASK) >> _ROUND_SHIFT);
}

int
fesetround(int __round)
{
	if (__round & ~_ROUND_MASK)
		return (-1);
	uint32_t fpcr = read_fpcr();
	fpcr &= ~(_ROUND_MASK << _ROUND_SHIFT);
	fpcr |= (__round & _ROUND_MASK) << _ROUND_SHIFT;
	write_fpcr(fpcr);
	return (0);
}

int
fegetenv(fenv_t *__envp)
{
	uint32_t fpcr = (read_fpcr() & (_ENABLE_MASK | (_ROUND_MASK << _ROUND_SHIFT)));
	uint32_t fpsr = (read_fpsr() & FE_ALL_EXCEPT);

	__envp->__fsr = (fpcr | fpsr);

	return (0);
}

int
feholdexcept(fenv_t *__envp)
{
	__envp->__fsr = 0;

	{
		uint32_t fpcr = read_fpcr();
		__envp->__fsr |= (fpcr & (_ENABLE_MASK | (_ROUND_MASK << _ROUND_SHIFT)));
		write_fpcr(fpcr & ~_ENABLE_MASK);
	}
	{
		uint32_t fpsr = read_fpsr();
		__envp->__fsr |= (fpsr & FE_ALL_EXCEPT);
		write_fpsr(fpsr & ~FE_ALL_EXCEPT);
	}

	return (0);
}

int
fesetenv(const fenv_t *__envp)
{
	write_fpcr(__envp->__fsr & (_ENABLE_MASK | (_ROUND_MASK << _ROUND_SHIFT)));
	write_fpsr(__envp->__fsr & FE_ALL_EXCEPT);

	return (0);
}

int
feupdateenv(const fenv_t *__envp)
{
	uint32_t fpsr = read_fpsr();
	write_fpcr(__envp->__fsr & (_ENABLE_MASK | (_ROUND_MASK << _ROUND_SHIFT)));
	write_fpsr(__envp->__fsr & FE_ALL_EXCEPT);
	feraiseexcept(fpsr & FE_ALL_EXCEPT);
	return (0);
}

#if __BSD_VISIBLE

/* We currently provide no external definitions of the functions below. */

int
feenableexcept(int __mask)
{
	uint32_t old_fpcr = read_fpcr();
	uint32_t new_fpcr = (old_fpcr | ((__mask & FE_ALL_EXCEPT) << _FPUSW_SHIFT));
	write_fpcr(new_fpcr);
	return ((old_fpcr >> _FPUSW_SHIFT) & FE_ALL_EXCEPT);
}

int
fedisableexcept(int __mask)
{
	uint32_t old_fpcr = read_fpcr();
	uint32_t new_fpcr = (old_fpcr & ~((__mask & FE_ALL_EXCEPT) << _FPUSW_SHIFT));
	write_fpcr(new_fpcr);
	return ((old_fpcr >> _FPUSW_SHIFT) & FE_ALL_EXCEPT);
}

int
fegetexcept(void)
{
	uint32_t old_fpcr = read_fpcr();
	return ((old_fpcr & _ENABLE_MASK) >> _FPUSW_SHIFT);
}

#endif /* __BSD_VISIBLE */

/*
 * Hopefully the system ID byte is immutable, so it's valid to use
 * this as a default environment.
 */
const fenv_t __fe_dfl_env = {0};

