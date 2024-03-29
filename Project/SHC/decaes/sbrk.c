/***********************************************************************/
/*                                                                     */
/*  FILE        :sbrk.c                                                */
/*  DATE        :Sat, Jul 12, 2008                                     */
/*  DESCRIPTION :Program of sbrk                                       */
/*  CPU TYPE    :Other                                                 */
/*                                                                     */
/*  This file is generated by Renesas Project Generator (Ver.4.5).     */
/*                                                                     */
/***********************************************************************/
                  


#include <stddef.h>
#include <stdio.h>
#include "sbrk.h"

//const size_t _sbrk_size=		/* Specifies the minimum unit of	*/
					/* the defined heap area		*/

extern char *_s1ptr;

#pragma pack 4
union HEAP_TYPE {
    long  dummy ;		/* Dummy for 4-byte boundary			*/
    char heap[HEAPSIZE];	/* Declaration of the area managed by sbrk	*/
};

static union HEAP_TYPE heap_area ;
//static __X union HEAP_TYPE heap_area__X;              /* for DSP-C */
//static __Y union HEAP_TYPE heap_area__Y;              /* for DSP-C */
#pragma unpack

/* End address allocated by sbrk	*/
static char *brk=(char *)&heap_area;
//static __X char *brk__X=(char __X *)&heap_area__X;    /* for DSP-C */
//static __Y char *brk__Y=(char __Y *)&heap_area__Y;    /* for DSP-C */

/**************************************************************************/
/*     sbrk:Memory area allocation                                        */
/*          Return value:Start address of allocated area (Pass)           */
/*                       -1                              (Failure)        */
/**************************************************************************/
char  *sbrk(unsigned long size)			/* Assigned area size	*/
{
      char  *p;

      if(brk+size>heap_area.heap+HEAPSIZE)	/* Empty area size	*/
	   return (char *)-1;

      p=brk;					/* Area assignment	*/
      brk += size;				/* End address update	*/
      return p ;
}

void abort() {
}

int write(int fileno, char *buf, unsigned int count) {
	return count;
}
/**************************************************************************/
/*     sbrk:X Memory area allocation                                      */
/*          Return value:Start address of allocated area (Pass)           */
/*                       -1                              (Failure)        */
//*      When the dspc option is specified at compiling, remove // of     */
//*      the head of the line which has /* for DSP-C */ and add start     */
//*      options and add "$XB" and "$YB" to the start option at linkage.  */
/**************************************************************************/
//char __X *sbrk__X(unsigned long size)	  /* Assigned area size	*/      /* for DSP-C */
//{                                                                     /* for DSP-C */
//    __X char *p;                                                      /* for DSP-C */
//                                                                      /* for DSP-C */
//    if (brk__X+size>heap_area__X.heap+HEAPSIZE) { /* Empty area size */ /* for DSP-C */
//        return (char __X *)-1;                                        /* for DSP-C */
//    }                                                                 /* for DSP-C */
//                                                                      /* for DSP-C */
//    p=brk__X;                   /* Area assignment */                 /* for DSP-C */
//    brk__X+=size;               /* End address update */              /* for DSP-C */
//    return p;                                                         /* for DSP-C */
//}                                                                     /* for DSP-C */

/**************************************************************************/
/*     sbrk:Y Memory area allocation                                      */
/*          Return value:Start address of allocated area (Pass)           */
/*                       -1                              (Failure)        */
//*      When the dspc option is specified at compiling, remove // of     */
//*      the head of the line which has /* for DSP-C */ and add start     */
//*      options and add "$XB" and "$YB" to the start option at linkage.  */
/**************************************************************************/
//char __Y *sbrk__Y(unsigned long size)    /* Assigned area size */     /* for DSP-C */
//{                                                                     /* for DSP-C */
//    __Y char *p;                                                      /* for DSP-C */
//                                                                      /* for DSP-C */
//    if (brk__Y+size>heap_area__Y.heap+HEAPSIZE) { /* Empty area size */ /* for DSP-C */
//        return (char __Y *)-1;                                        /* for DSP-C */
//    }                                                                 /* for DSP-C */
//    p=brk__Y;                    /* Area assignment */                /* for DSP-C */
//    brk__Y+=size;                /* End address update */             /* for DSP-C */
//    return p;                                                         /* for DSP-C */
//}                                                                     /* for DSP-C */
