;------------------------------------------------------------------------
;                                                                       |
;   FILE        :vect.inc                                               |
;   DATE        :Sat, Jul 12, 2008                                      |
;   DESCRIPTION :Definition of Vector                                   |
;   CPU TYPE    :Other                                                  |
;                                                                       |
;   This file is generated by Renesas Project Generator (Ver.4.5).      |
;                                                                       |
;------------------------------------------------------------------------
                  



;<<VECTOR DATA START (POWER ON RESET)>>
        ;H'000 Power On Reset (Hitachi-UDI RESET)
        .global	_PowerON_Reset                                                                                                                  
;<<VECTOR DATA END (POWER ON RESET)>>
;<<VECTOR DATA START (MANUAL RESET)>>
        ;H'020 Manual Reset
        .global	_Manual_Reset                                                                                                                   
;<<VECTOR DATA END (MANUAL RESET)>>
;<<VECTOR DATA START (TBL RESET)>>
        ;H'140 TBL Reset (DATA TBL Reset)
        .global         _TBL_Reset                                                                                                                      
;<<VECTOR DATA END (TBL RESET)>>

