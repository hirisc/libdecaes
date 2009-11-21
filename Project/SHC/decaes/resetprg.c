/***********************************************************************/
/*                                                                     */
/*  FILE        :resetprg.c                                            */
/*  DATE        :Sat, Jul 12, 2008                                     */
/*  DESCRIPTION :Reset Program                                         */
/*  CPU TYPE    :Other                                                 */
/*                                                                     */
/*  This file is generated by Renesas Project Generator (Ver.4.5).     */
/*                                                                     */
/***********************************************************************/
                  


#include	<machine.h>
#include	<_h_c_lib.h>
//#include	<stddef.h>					// Remove the comment when you use errno
//#include 	<stdlib.h>					// Remove the comment when you use rand()
#include	"stacksct.h"

#define SR_Init    0x000000F0
#define INT_OFFSET 0x100UL

#define RAMCR_ADDRESS       0xff00001c
#define RAMCR_INIT_VALUE    0x00000105

extern void INTHandlerPRG(void);
extern void PowerON_Reset_PC(void);
extern int main(int argc, char **argv);

//#ifdef __cplusplus				// Use SIM I/O
//extern "C" {
//#endif
//extern void _INIT_IOLIB(void);
//extern void _CLOSEALL(void);
//#ifdef __cplusplus
//}
//#endif

//extern void srand(unsigned int);	// Remove the comment when you use rand()
//extern char *_s1ptr;				// Remove the comment when you use strtok()
		
//#ifdef __cplusplus				// Use Hardware Setup
//extern "C" {
//#endif
//extern void HardwareSetup(void);
//#ifdef __cplusplus
//}
//#endif
	
//#ifdef __cplusplus			// Remove the comment when you use global class object
//extern "C" {					// Sections C$INIT and C$END will be generated
//#endif
//extern void _CALL_INIT(void);
//extern void _CALL_END(void);
//#ifdef __cplusplus
//}
//#endif

#pragma section ResetPRG

#pragma entry PowerON_Reset

void PowerON_Reset(void)
{ 
    unsigned long* ramcr_address;

	set_vbr((void *)((unsigned int)INTHandlerPRG - INT_OFFSET));
	_INITSCT();

//	_CALL_INIT();					// Remove the comment when you use global class object

//	_INIT_IOLIB();					// Use SIM I/O

//	errno=0;						// Remove the comment when you use errno
//	srand(1);						// Remove the comment when you use rand()
//	_s1ptr=NULL;					// Remove the comment when you use strtok()
		
//	HardwareSetup();				// Use Hardware Setup

    ramcr_address = (unsigned long*)RAMCR_ADDRESS;
    *ramcr_address = RAMCR_INIT_VALUE;
	set_cr(SR_Init);
    nop();

	main(1, 0);

//	_CLOSEALL();					// Use SIM I/O
	
//	_CALL_END();					// Remove the comment when you use global class object

	sleep();
}

//#pragma entry Manual_Reset			// Remove the comment when you use Manual Reset
void Manual_Reset(void)	
{
} 