#!/usr/bin/env python3
"""
D5FD File-based Parser Tool
Reads hex data from input file and writes parsed output to output file
"""

import re
import codecs
import sys
import os

class D5FDFileParser:
    def __init__(self, header_size="small"):
        self.header_size = header_size
        # Main header fields
        self.header_fields = [
            # Standard Header (ND5FDHDR)
            ("ND5FDBID", 0x000, 2, "BIT", "RECORD ID = X'D5FD'"),
            ("ND5FDCHK", 0x002, 1, "BIT", "RECORD CODE CHECK"),
            ("ND5FDCTL", 0x003, 1, "BIT", "CONTROL BYTE"),
            ("ND5FDPGM", 0x004, 4, "CHAR", "LAST PROGRAM TO FILE"),
            ("ND5FDFCH", 0x008, 4, "FA4", "FORWARD CHAIN ADDRESS"),
            ("ND5FDBCH", 0x00C, 4, "FA4", "BACKCHAIN ADDRESS"),
            ("SPARE1", 0x010, 16, "SPARE", "SPARES"),
            # BARTS Control Header (ND5FDCHD)
            ("ND5FDTYP", 0x020, 3, "CHAR", "BARTS RECORD TYPE"),
            ("ND5FDETK", 0x023, 1, "CHAR", "ELECTRONIC DOCUMENT"),
            ("ND5FDBNC", 0x024, 2, "CHAR", "BLOCK NBR IN CHAIN"),
            ("ND5FDNBC", 0x026, 2, "CHAR", "TOTAL NBR OF BLOCKS"),
            ("ND5FDSN1", 0x028, 2, "BIN", "SEQUENCE NBR OF BLOCK"),
            ("ND5FDSN2", 0x02A, 2, "BIN", "TOTAL NBR OF BLOCKS SENT"),
            ("ND5FDNAB", 0x02C, 2, "BIN", "NEXT AVAILABLE BYTE"),
            ("ND5FDCIR", 0x02E, 2, "BIN", "COUNT OF DATA ITEMS"),
            # System Security Controls (ND5FDSSC)
            ("ND5FDRTI", 0x030, 1, "BIT", "RETRANSMIT INDICATOR"),
            ("ND5FDEXT", 0x031, 1, "CHAR", "XT TAXES ELIMINATED"),
            ("ND5FDMUR", 0x032, 1, "CHAR", "BARTS USER INDICATOR"),
            ("SPARE2", 0x033, 1, "SPARE", "SPARE"),
            ("ND5FDH01", 0x034, 4, "BIN", "HASHTOTAL #1"),
            ("ND5FDH02", 0x038, 4, "BIN", "HASHTOTAL #2"),
            ("ND5FDH03", 0x03C, 2, "BIN", "HASHTOTAL #3"),
            ("ND5FDH04", 0x03E, 2, "BIN", "HASHTOTAL #4"),
            ("ND5FDH05", 0x040, 2, "BIN", "HASHTOTAL #5"),
            ("ND5FDH06", 0x042, 2, "BIN", "HASHTOTAL #6"),
            ("ND5FDH07", 0x044, 2, "BIN", "HASHTOTAL #7"),
            ("ND5FDH08", 0x046, 2, "BIN", "HASHTOTAL #8"),
            ("ND5FDH09", 0x048, 4, "BIN", "HASHTOTAL #9"),
            ("ND5FDH10", 0x04C, 2, "BIN", "HASHTOTAL #10"),
            ("ND5FDH11", 0x04E, 2, "BIN", "HASHTOTAL #11"),
            ("ND5FDH12", 0x050, 4, "BIN", "HASHTOTAL #12"),
            ("SPARE3", 0x054, 7, "SPARE", "SPARES"),
            ("ND5FDTER", 0x05B, 3, "BIT", "CONNECTIVITY TRANSMISSION ERRORS"),
            ("ND5FDTCI", 0x05E, 2, "BIN", "TOTAL COUNT OF ITINERARY SEGMENTS"),
        ]
        
        # TAR structure fields (ND5FDTAR) - offset from 0x060
        self.tar_fields = [
            ("ND5FDTKN", 0x000, 14, "CHAR", "TICKET NUMBER"),
            ("ND5FDCTN", 0x00E, 3, "CHAR", "CONJUNCTION TICKET NBR RANGE"),
            ("ND5FDPNL", 0x011, 6, "CHAR", "PNR LOCATOR"),
            ("ND5FDCCP", 0x017, 1, "BIT", "CREDIT CARD RESTRICTIONS"),
            ("ND5FDBDI", 0x018, 1, "CHAR", "BASE FARE DECIMAL INDICATOR"),
            ("ND5FDBEI", 0x019, 1, "CHAR", "INVOL/REISSUE BACKGROUND"),
            ("ND5FDTBS", 0x01A, 8, "PIC", "BASE FARE AMOUNT"),
            ("ND5FDTCC", 0x022, 3, "CHAR", "BASE FARE CURRENCY CODE"),
            ("ND5FDFCC", 0x025, 3, "CHAR", "TOTAL FARE CURRENCY CODE"),
            ("ND5FDTDI", 0x028, 1, "CHAR", "TOTAL FARE DECIMAL INDICATOR"),
            ("SPARE_TAR1", 0x029, 1, "SPARE", "SPARE BYTE"),
            ("ND5FDTTF", 0x02A, 8, "PIC", "TOTAL FARE"),
            ("ND5FDFTA", 0x032, 8, "PIC", "FARE TAX TOTAL AMOUNT"),
            ("ND5FDPTA", 0x03A, 8, "PIC", "FORM OF PAYMENT TAX TOTAL AMOUNT"),
            ("SPARE_TAR2", 0x042, 24, "SPARE", "SPARE BYTES"),
            ("ND5FDFPI", 0x05A, 1, "BIT", "FARE PRICING INDICATOR"),
            ("ND5FDFTI", 0x05B, 2, "CHAR", "FARE TYPE INDICATOR"),
            ("SPARE_TAR3", 0x05D, 3, "SPARE", "SPARE BYTES"),
            ("ND5FDTME", 0x060, 4, "CHAR", "TIME OF ACTIVITY (HHMM)"),
            ("ND5FDDTE", 0x064, 2, "BIN", "DATE OF ACTIVITY"),
            ("ND5FDCIC", 0x066, 3, "CHAR", "CITY CODE"),
            ("SPARE_TAR4", 0x069, 2, "SPARE", "SPARES - CITY CODE EXPANSION"),
            ("ND5FDOTN", 0x06B, 4, "CHAR", "OFFICE TYPE / NAME CODE"),
            ("SPARE_TAR5", 0x06F, 1, "SPARE", "SPARE BYTE"),
            ("ND5FDANS", 0x070, 5, "CHAR", "AGENT NUMERIC SINE"),
            ("ND5FDAGI", 0x075, 2, "CHAR", "AGENT ID"),
            ("SPARE_TAR6", 0x077, 1, "SPARE", "SPARE BYTE"),
            ("ND5FDASA", 0x078, 3, "BIT", "SET ADDR OF TICKET CREATION"),
            ("SPARE_TAR7", 0x07B, 1, "SPARE", "SPARE BYTE"),
            ("ND5FDIAC", 0x07C, 2, "CHAR", "ISSUING AIRLINE CODE"),
            ("SPARE_TAR8", 0x07E, 1, "SPARE", "SPARE - AIRLINE CODE EXPANSION"),
            ("ND5FDFPP", 0x07F, 1, "CHAR", "PURPOSE OF FOP"),
            ("ND5FDPTP", 0x080, 1, "CHAR", "PASSENGER TYPE CODE (PTC)"),
            ("SPARE_TAR9", 0x081, 7, "SPARE", "SPARE BYTES"),
            ("ND5FDTDF", 0x088, 1, "CHAR", "TICKET DATA ITEM AREA"),
        ]
        
        # ATR structure fields (ND5FDATR) - offset from 0x060
        self.atr_fields = [
            ("ND5FDWOU", 0x000, 2, "BIN", "COUNT OF TRANSACTION ENTRIES"),
            ("SPARE_ATR1", 0x002, 2, "SPARE", "SPARES"),
        ]
        
        # AIR structure fields (ND5FDAIR) - offset from 0x060
        self.air_fields = [
            ("ND5FDRTD", 0x000, 7, "CHAR", "AGENT ID"),
            ("SPARE_AIR1", 0x007, 1, "SPARE", "SPARE"),
            ("ND5FDRTC", 0x008, 2, "BIN", "COUNT OF TRANSACTION CODE ITEMS"),
        ]
        
        # IFR structure fields (ND5FDIFR) - offset from 0x060
        self.ifr_fields = [
            ("ND5FDCNT", 0x000, 2, "BIN", "COUNT OF IN-FLIGHT SALES DATA ENTRIES"),
            ("SPARE_IFR1", 0x002, 2, "SPARE", "SPARES"),
        ]
        
        # BOW structure fields (ND5FDBOW) - offset from 0x060
        self.bow_fields = [
            ("ND5FDDBD", 0x000, 7, "CHAR", "CREATION DATE"),
            ("ND5FDSSS", 0x007, 3, "CHAR", "STATION CODE"),
            ("ND5FDSLC", 0x00A, 4, "CHAR", "LOCATION CODE"),
            ("ND5FDPAD", 0x00E, 3, "BIT", "PRINTER ADDRESS"),
            ("ND5FDAII", 0x011, 8, "CHAR", "VOID AGENT ID"),
            ("SPARE_BOW1", 0x019, 1, "SPARE", "SPARE"),
            ("ND5FDSID", 0x01A, 10, "CHAR", "SECURITY ID"),
            ("ND5FDBTA", 0x024, 4, "BIT", "BTI FILE ADDRESS"),
        ]
        
        # COL structure fields (ND5FDCOL) - offset from 0x060
        self.col_fields = [
            ("ND5FDXFC", 0x000, 4, "CHAR", "OFFICE CODE"),
            ("ND5FDXTY", 0x004, 3, "CHAR", "CITY CODE"),
            ("SPARE_COL1", 0x007, 2, "SPARE", "SPARES"),
            ("ND5FDXLN", 0x009, 1, "BIT", "COLLECTION REPORT NUMBER"),
            ("ND5FDXLD", 0x00A, 2, "BIN", "COLLECTION REPORT DATE"),
            ("ND5FDXFD", 0x00C, 2, "BIN", "COLLECTION REPORT FROM DATE"),
            ("ND5FDXAI", 0x00E, 7, "CHAR", "SUMMARY AGENT ID"),
            ("ND5FDXID", 0x015, 7, "CHAR", "CLOSEOUT AGENT ID"),
            ("ND5FDXOD", 0x01C, 2, "BIN", "CLOSEOUT DATE"),
            ("ND5FDXON", 0x01E, 1, "BIT", "CLOSEOUT NUMBER"),
            ("ND5FDXI1", 0x01F, 1, "BIT", "AGENT TRANSACTION INDICATOR"),
            ("ND5FDRDF", 0x020, 1, "CHAR", "COLLECTION REPORT DATA"),
            ("SPARE_COL2", 0x021, 3, "SPARE", "SPARES"),
        ]


        # MIR structure fields (ND5FDMIR) - for MAR record type - offset from 0x060
        self.mir_fields = [
            # Sales Location Group (ND5FDVLO)
            ("ND5FDVFC", 0x000, 4, "CHAR", "OFFICE LOCATION"),
            ("ND5FDVTY", 0x004, 3, "CHAR", "CITY CODE"),
            ("SPARE_MIR1", 0x007, 2, "SPARE", "SPARES - CITY CODE EXPANSION"),
            
            # Basic Transaction Info
            ("ND5FDVID", 0x009, 7, "CHAR", "CREATING AGENT ID"),
            ("ND5FDVVD", 0x010, 2, "BIN", "ACTIVITY DATE"),
            ("ND5FDVYM", 0x012, 2, "BIN", "ACTIVITY TIME"),
            ("ND5FDVOC", 0x014, 14, "CHAR", "DOCUMENT NUMBER"),
            ("ND5FDVOJ", 0x022, 2, "CHAR", "CONJUNCTION TICKET NUMBER"),
            ("ND5FDVCR", 0x024, 3, "CHAR", "DOCUMENT CURRENCY CODE"),
            ("ND5FDVCA", 0x027, 6, "CHAR", "CREDIT CARD APPROVAL CODE"),
            ("ND5FDVOP", 0x02D, 37, "CHAR", "FORM OF PAYMENT TEXT"),
            ("ND5FDVOU", 0x052, 2, "BIN", "COUNT OF TRANSACTION CODE ITEMS"),
            ("ND5FDVTC", 0x054, 2, "BIN", "COUNT OF TAX TYPE ITEMS"),
            ("ND5FDVCI", 0x056, 1, "CHAR", "DOCUMENT DECIMAL INDICATOR"),
            ("ND5FDCRD", 0x057, 1, "BIT", "CREDIT CARD RESTRICTIONS"),
            
            # Transaction Code Items (3 x 12 bytes)
            ("ND5FDVVM1", 0x058, 4, "BIN", "TRANSACTION AMOUNT 1"),
            ("ND5FDVYP1", 0x05C, 3, "CHAR", "TRANSACTION CODE 1"),
            ("ND5FDVPF1", 0x05F, 1, "CHAR", "PASSENGER FACILITY CHARGE INDICATOR 1"),
            ("SPARE_CTI1", 0x060, 4, "SPARE", "SPARE BYTES 1"),

            ("ND5FDVVM2", 0x064, 4, "BIN", "TRANSACTION AMOUNT 2"),
            ("ND5FDVYP2", 0x068, 3, "CHAR", "TRANSACTION CODE 2"),
            ("ND5FDVPF2", 0x06B, 1, "CHAR", "PASSENGER FACILITY CHARGE INDICATOR 2"),
            ("SPARE_CTI2", 0x06C, 4, "SPARE", "SPARE BYTES 2"),

            ("ND5FDVVM3", 0x070, 4, "BIN", "TRANSACTION AMOUNT 3"),
            ("ND5FDVYP3", 0x074, 3, "CHAR", "TRANSACTION CODE 3"),
            ("ND5FDVPF3", 0x077, 1, "CHAR", "PASSENGER FACILITY CHARGE INDICATOR 3"),
            ("SPARE_CTI3", 0x078, 4, "SPARE", "SPARE BYTES 3"),
            
            # Tax Type Items (3 x 8 bytes)
            ("ND5FDTTI", 0x07C, 24, "CHAR", "TAX TYPE ITEMS (3x8)"),
            
            # Transaction Amounts
            ("ND5FDVAT", 0x094, 4, "BIN", "TRANSACTION TOTAL AMOUNT"),
            ("ND5FDVBS", 0x098, 4, "BIN", "ADDITIONAL COLLECTION BASE AMOUNT"),
            ("SPARE_MIR2", 0x09C, 2, "SPARE", "SPARE BYTES"),
            ("ND5FDVNT", 0x09E, 2, "BIN", "COUNT OF ADDITIONAL COLLECTION TAX ITEMS"),
            
            # Additional Collection Tax Items (3 x 8 bytes)
            ("ND5FDATE", 0x0A0, 24, "CHAR", "ADDITIONAL COLLECTION TAX ITEMS (3x8)"),
            
            ("ND5FDATA", 0x0B8, 4, "BIN", "ADDITIONAL COLLECTION TOTAL AMOUNT"),
            ("ND5FDVEP", 0x0BC, 2, "BIN", "DEPARTURE DATE"),
            ("ND5FDVRG", 0x0BE, 3, "CHAR", "ORIGIN STATION"),
            ("SPARE_MIR3", 0x0C1, 2, "SPARE", "SPARES - STATION CODE EXPANSION"),
            ("ND5FDACI", 0x0C3, 1, "CHAR", "REPS ACCOUNTING SYSTEM CODE"),
            
            # Routing Data (4 x 8 bytes)
            ("ND5FDVTG", 0x0C4, 32, "CHAR", "ROUTING DATA (4x8)"),            
            ("ND5FDVDN", 0x0E4, 14, "CHAR", "EXCHANGED DOCUMENT NUMBER"),
            ("ND5FDVDC", 0x0F2, 1, "BIT", "EXCHANGED DOCUMENT INDICATOR"),
            ("ND5FDXCG", 0x0F3, 4, "CHAR", "EXCHANGED DOCUMENT INDICATOR DATA"),
            ("ND5FDVKT", 0x0F7, 14, "CHAR", "TICKET-BY-MAIL TICKET NUMBER"),
            ("ND5FDVNR", 0x105, 2, "CHAR", "TICKET-BY-MAIL NUMBER RANGE"),
            ("ND5FDVAM", 0x107, 29, "CHAR", "TICKET-BY-MAIL NAME PURCHASER"),
            ("ND5FDQCT", 0x124, 4, "BIN", "AMOUNT TENDERED"),
            ("ND5FDQUR", 0x128, 3, "CHAR", "CURRENCY CODE OF AMOUNT TENDERED"),
            ("ND5FDQUS", 0x12B, 1, "CHAR", "TENDERED CURRENCY DECIMAL INDICATOR"),
            # Transaction Code Items (3 x 8 bytes each)
            ("ND5FDQAM1", 0x12C, 4, "BIN", "TRANSACTION AMOUNT 1"),
            ("ND5FDQYP1", 0x130, 3, "CHAR", "TRANSACTION CODE 1"),
            ("SPARE_QT1", 0x133, 1, "SPARE", "SPARE BYTE 1"),
            ("ND5FDQAM2", 0x134, 4, "BIN", "TRANSACTION AMOUNT 2"),
            ("ND5FDQYP2", 0x138, 3, "CHAR", "TRANSACTION CODE 2"),
            ("SPARE_QT2", 0x13B, 1, "SPARE", "SPARE BYTE 2"),
            ("ND5FDQAM3", 0x13C, 4, "BIN", "TRANSACTION AMOUNT 3"),
            ("ND5FDQYP3", 0x140, 3, "CHAR", "TRANSACTION CODE 3"),
            ("SPARE_QT3", 0x143, 1, "SPARE", "SPARE BYTE 3"),
            # Tax Code Items (3 x 8 bytes each)
            ("ND5FDQAX1", 0x144, 4, "BIN", "TAX AMOUNT 1"),
            ("ND5FDQCD1", 0x148, 2, "CHAR", "TAX CODE 1"),
            ("SPARE_QE1", 0x14A, 2, "SPARE", "SPARE BYTES 1"),
            ("ND5FDQAX2", 0x14C, 4, "BIN", "TAX AMOUNT 2"),
            ("ND5FDQCD2", 0x150, 2, "CHAR", "TAX CODE 2"),
            ("SPARE_QE2", 0x152, 2, "SPARE", "SPARE BYTES 2"),
            ("ND5FDQAX3", 0x154, 4, "BIN", "TAX AMOUNT 3"),
            ("ND5FDQCD3", 0x158, 2, "CHAR", "TAX CODE 3"),
            ("SPARE_QE3", 0x15A, 2, "SPARE", "SPARE BYTES 3"),
            ("ND5FDQDC", 0x15C, 10, "CHAR", "DOCUMENT CURRENCY EXCHANGE RATE"),
            ("ND5FDVPC", 0x166, 2, "BIN", "TOTAL PASSENGER COUNT FOR PFC'S"),
            ("ND5FDCRT", 0x168, 3, "PIC", "COMMISSION RATE FOR GSA TRANSACTIONS"),
            ("ND5FDREP", 0x16B, 14, "CHAR", "REPRINT DOCUMENT NUMBER"),
            ("ND5FDCOM", 0x179, 11, "CHAR", "COMMISSION AMOUNT"),
            ("ND5FDCLT", 0x184, 2, "CHAR", "REPS CARD LEVEL RESULTS"),
            ("ND5FDFRE", 0x186, 10, "CHAR", "FREQUENT FLYER NUMBER"),
            ("ND5FDRAS", 0x190, 3, "BIT", "AGENT SET ADDRESS"),
            ("ND5FDMPS", 0x193, 1, "CHAR", "REPS AUTHORIZATION CHARACTERISTICS INDICATOR"),
            ("ND5FDMVC", 0x194, 4, "CHAR", "REPS VALIDATION CODE"),
            ("ND5FDMTR", 0x198, 9, "CHAR", "REPS TRANSACTION ID/BANKNET REFERENCE NUMBER"),
            ("ND5FDMST", 0x1A1, 2, "CHAR", "REPS AUTHORIZATION RESPONSE/DOWNGRADE INDICATOR"),
            ("ND5FDRAC", 0x1A3, 1, "CHAR", "REPS AUTHORIZATION SOURCE CODE"),
            ("ND5FDPOS", 0x1A4, 2, "CHAR", "REPS POS ENTRY MODE"),
            ("ND5FDBNT", 0x1A6, 2, "BIN", "REPS BANKNET REFERENCE DATE"),
            ("ND5FDECI", 0x1A8, 2, "CHAR", "REPS ELECTRONIC COMMERCE INDICATOR (ECI)"),
            ("ND5FDCAV", 0x1AA, 1, "CHAR", "REPS CARDHOLDER AUTHENTICATION VERIFICATION VALUE (CAVV)"),
            ("ND5FDTIC", 0x1AB, 1, "CHAR", "REPS CARDHOLDER ACTIVATION TERMINAL ID (CAT)"),
            
            # Flight Data (4 x 12 bytes)
            ("ND5FDQFD", 0x1AC, 48, "CHAR", "ROUTING DATA (4x12)"),
            
            ("ND5FDVOL", 0x1DC, 1, "CHAR", "VOL/INVOL INDICATOR"),
            ("ND5FDRSN", 0x1DD, 3, "CHAR", "REASON CODE"),
            ("ND5FDARD", 0x1E0, 15, "CHAR", "REPS ACQUIRER REFERENCE DATA (ARD)"),
            ("ND5FDPSD", 0x1EF, 12, "CHAR", "REPS POINT OF SERVICE DATA (PSD)"),
            ("ND5FDAVS", 0x1FB, 1, "CHAR", "ADDRESS VERIFICATION INDICATOR"),
            ("ND5FDRL4", 0x1FC, 4, "CHAR", "REPS LAST FOUR DIGITS OF CREDIT CARD NUMBER"),
            ("ND5FDRSD", 0x200, 1, "CHAR", "REPS ACCOUNT STATUS DATA"),
            ("SPARE_MIR4", 0x201, 9, "SPARE", "SPARES"),
            ("ND5FDRTR", 0x20A, 11, "CHAR", "REPS TOKEN REQUESTOR ID DATA"),
            ("ND5FDRTL", 0x215, 2, "CHAR", "REPS TOKEN ASSURE LEVEL DATA"),
            ("ND5FDRSI", 0x217, 1, "CHAR", "REPS SPEND QUALIFIED INDICATOR"),
            ("ND5FDSP1", 0x218, 1, "CHAR", "REPS SECURITY PROTOCOL"),
            ("ND5FDTRC", 0x219, 2, "CHAR", "REPS TRANSACTION INTEGRITY CLASS (TIC)"),
            ("ND5FDPAN", 0x21B, 35, "CHAR", "REPS PAYMENT ACCOUNT REFERENCE NUMBER"),
            ("ND5FDADI", 0x23E, 1, "CHAR", "REPS MARKET SPECIFIC AUTHORIZATION DATA INDICATOR"),
            ("ND5FDSTA", 0x23F, 6, "CHAR", "REPS SYSTEM TRACE AUDIT NUMBER (STAN)"),
            ("ND5FDTDC", 0x245, 2, "CHAR", "REPS TRANSACTION DATA CONDITION CODE"),
            ("ND5FDPS2", 0x247, 13, "CHAR", "REPS POS DATA"),
            ("ND5FDPRC", 0x254, 6, "CHAR", "REPS PROCESSING CODE"),
            ("ND5FDCAN", 0x25A, 1, "CHAR", "REPS CARDHOLDER AUTHENTICATION"),
            ("ND5FDSCI", 0x25B, 1, "CHAR", "REPS STORED CREDENTIAL INDICATOR"),
            ("ND5FDAAV", 0x25C, 32, "CHAR", "REPS ACCOUNTHOLDER AUTHENTICATION VALUE"),
            ("ND5FDSTI", 0x27C, 36, "CHAR", "REPS DIRECTORY SERVER TRANSACTION ID"),
            ("ND5FDPPC", 0x2A0, 1, "CHAR", "REPS PROGRAM PROTOCOL"),
            
            # Contactless REPS Data - Individual Fields within ND5FDCRP Group
            ("ND5FDAAM", 0x2A1, 13, "CHAR", "TAG=9F02 AUTHORIZED AMOUNT"),
            ("ND5FDAIP", 0x2AE, 4, "CHAR", "TAG=82 APPLICATION INTERCHANGE PROFILE"),
            ("ND5FDARC", 0x2B2, 16, "CHAR", "TAG=9F26 APPLICATION REQUEST CRYPTOGRAM"),
            ("ND5FDATC", 0x2C2, 4, "CHAR", "TAG=9F36 APPLICATION TRANSACTION COUNTER"),
            ("ND5FDAUC", 0x2C6, 4, "CHAR", "TAG=5F2A AUTHORIZATION CURRENCY CODE"),
            ("ND5FDADT", 0x2CA, 6, "CHAR", "TAG=9A AUTHORIZATION DATE"),
            ("ND5FDCDT", 0x2D0, 2, "CHAR", "TAG=9F27 CRYPTOGRAM INFORMATION DATA"),
            ("ND5FDCTT", 0x2D2, 2, "CHAR", "TAG=9C CRYPTOGRAM TRANSACTION TYPE"),
            ("ND5FDCSN", 0x2D4, 3, "CHAR", "TAG=5F34 CARD SEQUENCE NUMBER"),
            ("ND5FDCVM", 0x2D7, 6, "CHAR", "TAG=9F34 CARDHOLDER VERIFICATION METHOD"),
            ("ND5FDCCC", 0x2DD, 1, "CHAR", "CHIP CONDITION CODE"),
            ("ND5FDDFN", 0x2DE, 32, "CHAR", "TAG=84 DEDICATED FILE NAME"),
            ("ND5FDDTC", 0x2FE, 2, "CHAR", "DEVICE TYPE"),
            ("ND5FDFFT", 0x300, 8, "CHAR", "TAG=9F6E FORM FACTOR"),
            ("ND5FDIFD", 0x308, 16, "CHAR", "TAG=9F1E INTERFACE DEVICE (IFD) SERIAL NO"),
            ("ND5FDIAD", 0x318, 64, "CHAR", "TAG=9F10 ISSUER APPLICATION DATA (IAD)"),
            ("ND5FDIRO", 0x358, 24, "CHAR", "TAG=71 ISSUER SCRIPT RESULTS PART I"),
            ("ND5FDIRT", 0x370, 18, "CHAR", "TAG=72 ISSUER SCRIPT RESULTS PART II"),
            ("ND5FDTKD", 0x382, 2, "CHAR", "TAG=9F53 TRANSACTION CATEGORY CODE"),
            ("ND5FDTSC", 0x384, 8, "CHAR", "TAG=9F41 TRANSACTION SEQUENCE COUNTER"),
            ("ND5FDTAV", 0x38C, 4, "CHAR", "TAG=9F09 TERMINAL APPLICATION VERSION NO"),
            ("ND5FDTCP", 0x390, 6, "CHAR", "TAG=9F33 TERMINAL CAPABILITIES PROFILE"),
            ("ND5FDTCO", 0x396, 4, "CHAR", "TAG=9F1A TERMINAL COUNTRY CODE"),
            ("ND5FDTTD", 0x39A, 6, "CHAR", "TAG=9A TERMINAL TRANSMISSION DATE"),
            ("ND5FDTTY", 0x3A0, 2, "CHAR", "TAG=9F35 TERMINAL TYPE"),
            ("ND5FDTVR", 0x3A2, 10, "CHAR", "TAG=95 TERMINAL VERIFICATION RESULTS"),
            ("ND5FDUNN", 0x3AC, 8, "CHAR", "TAG=9F37 UNPREDICTABLE NUMBER"),
            ("ND5FDMPE", 0x3B4, 32, "CHAR", "PAYMENT REFERENCE ID"),

            # Fill remaining space to complete 3998 bytes  
            ("MIR_REMAINING", 0x3D4, 3998-0x3D4, "SPARE", "REMAINING MIR STRUCTURE DATA"),
        ]
        
        # MAR structure fields (ND5FDMAR) - offset from 0x060
        self.mar_fields = [
            # Fixed length fields (880 bytes)
            ("SPARE_MAR1", 0x000, 2, "SPARE", "SPARES"),
            
            # Ticketing City Information
            ("ND5FDMCI", 0x002, 3, "CHAR", "TICKETING CITY"),
            ("SPARE_MAR2", 0x005, 3, "SPARE", "SPARES"),
            ("ND5FDMTG", 0x008, 2, "CHAR", "TICKETING TELETYPE ADDRESS"),
            ("ND5FDMAL", 0x00A, 2, "CHAR", "TICKETING AIRLINE"),
            ("SPARE_MAR3", 0x00C, 2, "SPARE", "SPARES"),
            
            # Passenger Names (2 x 29 bytes)
            ("ND5FDMNS1", 0x00E, 29, "CHAR", "PASSENGER NAME 1"),
            ("ND5FDMNS2", 0x02B, 29, "CHAR", "PASSENGER NAME 2"),
            ("SPARE_MAR4", 0x048, 2, "SPARE", "SPARES"),
            
            # MCO Number Information
            ("ND5FDMMN", 0x04A, 14, "CHAR", "MCO NUMBER"),
            ("ND5FDMDN", 0x058, 1, "CHAR", "DUPE MCO NBR INDICATOR"),
            ("SPARE_MAR5", 0x059, 1, "SPARE", "SPARE"),
            ("ND5FDMON", 0x05A, 14, "CHAR", "OLD MCO NUMBER"),
            ("SPARE_MAR6", 0x068, 2, "SPARE", "SPARES"),
            ("ND5FDMID", 0x06A, 7, "CHAR", "ISSUE DATE"),
            ("SPARE_MAR7", 0x071, 1, "SPARE", "SPARE"),
            
            # Activity Information
            ("ND5FDMCT", 0x072, 3, "CHAR", "CITY"),
            ("SPARE_MAR8", 0x075, 3, "SPARE", "SPARES"),
            ("ND5FDMSI", 0x078, 2, "CHAR", "SELLING TELETYPE ADDRESS"),
            ("ND5FDMAA", 0x07A, 2, "CHAR", "AIRLINE"),
            ("SPARE_MAR9", 0x07C, 2, "SPARE", "SPARES"),
            ("ND5FDMOC", 0x07E, 4, "CHAR", "OFFICE CODE"),
            ("ND5FDMAG", 0x082, 5, "CHAR", "AGENT NUMERIC SINE"),
            ("ND5FDMAN", 0x087, 2, "CHAR", "AGENT ID"),
            ("SPARE_MAR10", 0x089, 1, "SPARE", "SPARE"),
            ("ND5FDMCY", 0x08A, 3, "CHAR", "CITY CODE"),
            ("SPARE_MAR11", 0x08D, 2, "SPARE", "SPARES"),
            ("ND5FDMOF", 0x08F, 4, "CHAR", "OFFICE TYPE/NAME CODE"),
            ("SPARE_MAR12", 0x093, 1, "SPARE", "SPARE"),
            ("ND5FDMDT", 0x094, 2, "BIN", "DATE (Local Binary Day NBR)"),
            ("ND5FDMTM", 0x096, 4, "CHAR", "TIME (Local)"),
            ("ND5FDMAD", 0x09A, 6, "CHAR", "AGENT SET ADDRESS"),
            ("SPARE_MAR13", 0x0A0, 6, "SPARE", "SPARES"),
            
            # Base Fare Amount
            ("ND5FDMBC", 0x0A6, 3, "CHAR", "BASE FARE CURRENCY CODE"),
            ("SPARE_MAR14", 0x0A9, 1, "SPARE", "SPARE"),
            ("ND5FDMBI", 0x0AA, 1, "CHAR", "BASE FARE DECIMAL INDICATOR"),
            ("SPARE_MAR15", 0x0AB, 1, "SPARE", "SPARE"),
            ("ND5FDMBA", 0x0AC, 8, "PIC", "BASE FARE AMOUNT"),
            
            # Equivalent Fare Paid
            ("ND5FDMEC", 0x0B4, 3, "CHAR", "EQUIVALENT FARE CURRENCY CODE"),
            ("SPARE_MAR16", 0x0B7, 1, "SPARE", "SPARE"),
            ("ND5FDMEA", 0x0B8, 8, "PIC", "EQUIVALENT FARE AMOUNT"),
            ("SPARE_MAR17", 0x0C0, 2, "SPARE", "SPARES"),
            
            # Tax Amounts
            ("ND5FDMFC", 0x0C2, 2, "CHAR", "FIRST TAX CODE"),
            ("SPARE_MAR18", 0x0C4, 2, "SPARE", "SPARES"),
            ("ND5FDMFX", 0x0C6, 6, "PIC", "FIRST TAX AMOUNT"),
            ("SPARE_MAR19", 0x0CC, 2, "SPARE", "SPARES"),
            ("ND5FDMSC", 0x0CE, 2, "CHAR", "SECOND TAX CODE"),
            ("SPARE_MAR20", 0x0D0, 2, "SPARE", "SPARES"),
            ("ND5FDMSX", 0x0D2, 6, "PIC", "SECOND TAX AMOUNT"),
            ("SPARE_MAR21", 0x0D8, 2, "SPARE", "SPARES"),
            ("SPARE_MAR22", 0x0DA, 2, "SPARE", "SPARES"),
            ("ND5FDMTE", 0x0DC, 2, "CHAR", "THIRD TAX CODE"),
            ("SPARE_MAR23", 0x0DE, 2, "SPARE", "SPARES"),
            ("ND5FDMTX", 0x0E0, 6, "PIC", "THIRD TAX AMOUNT"),
            ("SPARE_MAR24", 0x0E6, 14, "SPARE", "SPARES"),
            
            # Totals
            ("ND5FDMCC", 0x0F4, 3, "CHAR", "TICKET TOTAL CURRENCY CODE"),
            ("SPARE_MAR25", 0x0F7, 1, "SPARE", "SPARE"),
            ("ND5FDMTO", 0x0F8, 8, "PIC", "TICKET TOTAL"),
            ("SPARE_MAR26", 0x100, 2, "SPARE", "SPARES"),
            ("ND5FDMMC", 0x102, 3, "CHAR", "MISCELLANEOUS TOTAL CURRENCY CODE"),
            ("SPARE_MAR27", 0x105, 1, "SPARE", "SPARE"),
            ("ND5FDMMA", 0x106, 8, "PIC", "MISCELLANEOUS TOTAL"),
            ("SPARE_MAR28", 0x10E, 2, "SPARE", "SPARES"),
            ("ND5FDMPC", 0x110, 3, "CHAR", "PTA TOTAL CURRENCY CODE"),
            ("SPARE_MAR29", 0x113, 1, "SPARE", "SPARE"),
            ("ND5FDMPI", 0x114, 1, "CHAR", "PTA Total Decimal Indicator"),
            ("SPARE_MAR30", 0x115, 1, "SPARE", "SPARE"),
            ("ND5FDMPA", 0x116, 8, "PIC", "PTA TOTAL"),
            
            # Service Charge
            ("ND5FDMSO", 0x11E, 3, "CHAR", "Service Charge CURRENCY CODE"),
            ("SPARE_MAR31", 0x121, 1, "SPARE", "SPARE"),
            ("ND5FDMSA", 0x122, 6, "PIC", "Service Charge Amount"),
            ("SPARE_MAR32", 0x128, 2, "SPARE", "SPARES"),
            
            # Purchaser Information
            ("ND5FDMPN", 0x12A, 29, "CHAR", "PURCHASER NAME"),
            ("SPARE_MAR33", 0x147, 1, "SPARE", "SPARE"),
            ("ND5FDMPR", 0x148, 175, "CHAR", "PURCHASER ADDRESS"),
            ("SPARE_MAR34", 0x1F7, 1, "SPARE", "SPARE"),
            ("ND5FDMPP", 0x1F8, 80, "CHAR", "PURCHASER PHONE"),
            ("ND5FDMCP", 0x248, 29, "CHAR", "CARD PRESENTED BY NAME"),
            ("SPARE_MAR35", 0x265, 1, "SPARE", "SPARE"),
            ("ND5FDMIA", 0x266, 8, "CHAR", "IATA NUMBER"),
            ("SPARE_MAR36", 0x26E, 2, "SPARE", "SPARES"),
            
            # Commission
            ("ND5FDMIN", 0x270, 1, "CHAR", "COMMISSION TYPE INDICATOR"),
            ("SPARE_MAR37", 0x271, 1, "SPARE", "SPARE"),
            ("ND5FDMCN", 0x272, 11, "PIC", "COMMISSION RATE OR AMOUNT"),
            ("SPARE_MAR38", 0x27D, 1, "SPARE", "SPARE"),
            
            # Form of Payment
            ("ND5FDMFO", 0x27E, 58, "CHAR", "FORM OF PAYMENT"),
            ("ND5FDMCA", 0x2B8, 6, "CHAR", "CREDIT CARD APPROVAL CODE"),
            ("SPARE_MAR39", 0x2BE, 4, "SPARE", "SPARES"),
            
            # Residual Value
            ("ND5FDMRC", 0x2C2, 3, "CHAR", "TOTAL RESIDUAL VALUE CURRENCY CODE"),
            ("SPARE_MAR40", 0x2C5, 1, "SPARE", "SPARE"),
            ("ND5FDMRA", 0x2C6, 8, "PIC", "TOTAL RESIDUAL VALUE AMOUNT"),
            ("SPARE_MAR41", 0x2CE, 2, "SPARE", "SPARES"),
            
            # Remarks and Routing
            ("ND5FDMRI", 0x2D0, 57, "CHAR", "REMARKS INFORMATION"),
            ("ND5FDMRT", 0x309, 57, "CHAR", "ROUTING INFORMATION"),
            
            # Flight Information
            ("ND5FDMFD", 0x342, 2, "BIN", "FLIGHT DATE"),
            ("ND5FDMCD", 0x344, 2, "CHAR", "AIRLINE CODE"),
            ("SPARE_MAR42", 0x346, 2, "SPARE", "SPARES"),
            ("ND5FDMBO", 0x348, 3, "CHAR", "BOARDING CITY"),
            ("SPARE_MAR43", 0x34B, 3, "SPARE", "SPARES"),
            ("ND5FDMFN", 0x34E, 2, "BIT", "FLIGHT NUMBER"),
            
            # Bankers Rate
            ("ND5FDMBR", 0x350, 15, "PIC", "BANKERS BUYING RATE"),
            ("SPARE_MAR44", 0x35F, 1, "SPARE", "SPARE"),
            
            # Activity Indicators
            ("ND5FDMCR", 0x360, 1, "CHAR", "NEWLY CREATED PTA"),
            ("SPARE_MAR45", 0x361, 1, "SPARE", "SPARE"),
            ("ND5FDMCM", 0x362, 1, "CHAR", "UPDATE TO CHANGE MCO NBR"),
            ("SPARE_MAR46", 0x363, 1, "SPARE", "SPARE"),
            ("ND5FDMUS", 0x364, 1, "CHAR", "UPDATE AND PNR SPLIT"),
            ("SPARE_MAR47", 0x365, 1, "SPARE", "SPARE"),
            ("ND5FDMUP", 0x366, 1, "CHAR", "UPDATE AND PNR NOT SPLIT"),
            ("SPARE_MAR48", 0x367, 1, "SPARE", "SPARE"),
            ("ND5FDMSP", 0x368, 1, "CHAR", "PTA NOT UPDATED BUT PNR SPLIT"),
            ("SPARE_MAR49", 0x369, 1, "SPARE", "SPARE"),
            ("ND5FDMDR", 0x36A, 1, "CHAR", "DELTA SOLD PTA CREDIT CARD REFUND"),
            ("SPARE_MAR50", 0x36B, 1, "SPARE", "SPARE"),
            ("ND5FDMRD", 0x36C, 1, "CHAR", "OTHER REFUND"),
            ("SPARE_MAR51", 0x36D, 1, "SPARE", "SPARE"),
            ("ND5FDMMS", 0x36E, 1, "CHAR", "MISCELLANEOUS FUNDS USED"),
            ("SPARE_MAR52", 0x36F, 1, "SPARE", "SPARE"),
            
            # Start of variable data items
            ("ND5FDMDI", 0x370, 1, "CHAR", "START OF PREPAID DATA ITEMS"),
        ]
        
        # VOI structure fields (ND5FDVOI) - offset from 0x060
        self.voi_fields = [
            ("ND5FDVNB", 0x000, 14, "CHAR", "DOCUMENT NUMBER"),
            ("ND5FDVCJ", 0x00E, 2, "CHAR", "CONJUNCTION NUMBER"),
            ("ND5FDVCD", 0x010, 2, "BIN", "CREATION DATE (PARS BINARY DAY NBR)"),
            ("ND5FDVAG", 0x012, 7, "CHAR", "CREATING AGENT ID"),
            ("ND5FDVVA", 0x019, 7, "CHAR", "VOID AGENT ID"),
            ("ND5FDVSL", 0x020, 7, "CHAR", "SALES LOCATION"),
            ("ND5FDVOT", 0x027, 1, "CHAR", "VOID TYPE"),
            ("ND5FDORT", 0x028, 1, "CHAR", "ORIGINAL REFUND TYPE"),
            ("SPARE_VOI", 0x029, 9, "SPARE", "SPARES"),
        ]
        
        # REF structure fields (ND5FDREF) - offset from 0x060
        self.ref_fields = [
            ("ND5FDREC", 0x000, 14, "CHAR", "REFUND RECEIPT NUMBER"),
            ("ND5FDCCA", 0x00E, 21, "CHAR", "TYPE OF PAYMENT"),
            ("ND5FDPCN", 0x023, 29, "CHAR", "PASSENGER NAME"),
            ("ND5FDRCR", 0x040, 3, "CHAR", "CURRENCY CODE"),
            ("ND5FDINV", 0x043, 1, "CHAR", "INVOLUNTARY INDICATOR"),
            ("ND5FDORG", 0x044, 3, "CHAR", "ORIGIN CITY CODE"),
            ("ND5FDDES", 0x047, 3, "CHAR", "DESTINATION CITY CODE"),
            ("ND5FDTRA", 0x04A, 8, "CHAR", "TRAVEL AGY IDENTIFIER-IATA"),
            ("ND5FDAGY", 0x052, 5, "CHAR", "AGENCY COMMISSION"),
            ("ND5FDISS", 0x057, 3, "CHAR", "ISSUING CARRIER"),
            ("ND5FDFAA", 0x05A, 8, "CHAR", "FARE AMOUNT"),
            ("ND5FDTC1", 0x062, 3, "CHAR", "1ST MISC TRANSACTION CODE"),
            ("ND5FDTC2", 0x065, 3, "CHAR", "2ND MISC TRANSACTION CODE"),
            ("ND5FDTC3", 0x068, 3, "CHAR", "3RD MISC TRANSACTION CODE"),
            ("ND5FDTA1", 0x06B, 8, "CHAR", "1ST MISC TRANSACTION AMOUNT"),
            ("ND5FDTA2", 0x073, 8, "CHAR", "2ND MISC TRANSACTION AMOUNT"),
            ("ND5FDTA3", 0x07B, 8, "CHAR", "3RD MISC TRANSACTION AMOUNT"),
            ("ND5FDKN1", 0x0B0, 14, "CHAR", "1ST REFUNDED TICKET NUMBER"),
            ("ND5FDKN2", 0x0BE, 14, "CHAR", "2ND REFUNDED TICKET NUMBER"),
            ("ND5FDKN3", 0x0CC, 14, "CHAR", "3RD REFUNDED TICKET NUMBER"),
            ("ND5FDKN4", 0x0DA, 14, "CHAR", "4TH REFUNDED TICKET NUMBER"),
            ("ND5FDKN5", 0x0E8, 14, "CHAR", "5TH REFUNDED TICKET NUMBER"),
            ("ND5FDCN1", 0x0F6, 4, "CHAR", "1ST REFUNDED TICKET COUPON"),
            ("ND5FDCN2", 0x0FA, 4, "CHAR", "2ND REFUNDED TICKET COUPON"),
            ("ND5FDCN3", 0x0FE, 4, "CHAR", "3RD REFUNDED TICKET COUPON"),
            ("ND5FDCN4", 0x102, 4, "CHAR", "4TH REFUNDED TICKET COUPON"),
            ("ND5FDCN5", 0x106, 4, "CHAR", "5TH REFUNDED TICKET COUPON"),
            ("ND5FDPNG", 0x10A, 3, "CHAR", "PENALTY CHARGE CODE - PEN"),
            ("ND5FDNT2", 0x10D, 7, "CHAR", "PENALTY CHARGE AMOUNT"),
            ("ND5FDTRT", 0x114, 8, "CHAR", "TOTAL REFUNDED AMOUNT"),
            ("ND5FDSTM", 0x11C, 7, "CHAR", "SYSTEM DATE"),
            ("ND5FDELC", 0x123, 7, "CHAR", "SALES LOCATION"),
            ("ND5FDATD", 0x12A, 7, "CHAR", "AGENT ID"),
            ("ND5FDCOD", 0x131, 3, "CHAR", "ADMIN SERVICE CHG CODE - ASC"),
            ("ND5FDCOS", 0x134, 7, "CHAR", "ADMIN SERVICE CHG AMT"),
            ("ND5FDOTC", 0x1E0, 3, "CHAR", "OTHER MISC CHARGES CODE"),
            ("ND5FDOTA", 0x1E3, 7, "CHAR", "OTHER MISC CHARGES AMOUNT"),
            ("ND5FDPRI", 0x1EA, 1, "CHAR", "PROCESSING INDICATOR"),
            ("ND5FDPNM", 0x290, 38, "CHAR", "PAYEE NAME"),
            ("ND5FDAD1", 0x2B6, 30, "CHAR", "PAYEE ADDRESS 1"),
            ("ND5FDAD2", 0x2D4, 30, "CHAR", "PAYEE ADDRESS 2"),
            ("ND5FDCTY", 0x2F2, 15, "CHAR", "CITY"),
            ("ND5FDSUB", 0x301, 2, "CHAR", "SUBCOUNTRY"),
            ("ND5FDCTR", 0x303, 3, "CHAR", "COUNTRY"),
            ("ND5FDZIP", 0x306, 9, "CHAR", "ZIP CODE"),
            ("ND5FDREA", 0x30F, 1, "CHAR", "REASON FOR REFUND"),
            ("ND5FDDTI", 0x310, 2, "BIN", "ORIGINAL DATE TKT ISSUED"),
            ("ND5FDCKN", 0x312, 15, "CHAR", "REFUND CHECK NUMBER"),
            ("ND5FDDCI", 0x321, 2, "BIN", "DATE REFUND CHECK ISSUED"),
            ("ND5FDFFN", 0x323, 10, "CHAR", "FREQUENT FLYER NUMBER"),
            ("ND5FDFTN", 0x32D, 4, "CHAR", "FLIGHT NUMBER"),
            ("ND5FDFDT", 0x331, 2, "BIN", "FLIGHT DATE"),
            ("ND5FDDNR", 0x333, 14, "CHAR", "REPRINT DOCUMENT NUMBER"),
            ("ND5FDREI", 0x341, 1, "CHAR", "REFUND/EXCHANGE INDICATOR"),
            ("ND5FDPEI", 0x342, 1, "CHAR", "PAPER/ELECTRONIC INDICATOR"),
            ("ND5FDNTN", 0x343, 13, "CHAR", "NEW TICKET NUMBER"),
            ("ND5FDAMT", 0x350, 11, "CHAR", "REFUND AMOUNT COMPUTED"),
            ("ND5FDRMK", 0x35B, 55, "CHAR", "REMARKS FROM TEMPLATE"),
            ("ND5FDRM2", 0x392, 30, "CHAR", "SECOND LINE OF REMARKS"),
            ("ND5FDRRD", 0x3B0, 7, "CHAR", "REFUND REQUEST DATE"),
            ("ND5FDARF", 0x3B7, 1, "BIT", "CREDIT CARD RESTRICTIONS"),
            ("SPARE_REF1", 0x3B8, 8, "SPARE", "SPARES"),
            
            # Refund Taxes (99 x 16 bytes each) - break down first few entries
            ("ND5FD99C1", 0x3C0, 2, "CHAR", "TAX CODE 1"),
            ("SPARE_TX1", 0x3C2, 3, "SPARE", "SPARES 1"),
            ("ND5FD99T1", 0x3C5, 11, "CHAR", "TAX AMOUNT 1"),
            
            ("ND5FD99C2", 0x3D0, 2, "CHAR", "TAX CODE 2"),
            ("SPARE_TX2", 0x3D2, 3, "SPARE", "SPARES 2"),
            ("ND5FD99T2", 0x3D5, 11, "CHAR", "TAX AMOUNT 2"),
            
            ("ND5FD99C3", 0x3E0, 2, "CHAR", "TAX CODE 3"),
            ("SPARE_TX3", 0x3E2, 3, "SPARE", "SPARES 3"),
            ("ND5FD99T3", 0x3E5, 11, "CHAR", "TAX AMOUNT 3"),

            ("ND5FD99C4", 0x3F0, 2, "CHAR", "TAX CODE 4"),
            ("SPARE_TX4", 0x3F2, 3, "SPARE", "SPARES 4"),
            ("ND5FD99T4", 0x3F5, 11, "CHAR", "TAX AMOUNT 4"),

            ("ND5FD99C5", 0x400, 2, "CHAR", "TAX CODE 5"),
            ("SPARE_TX5", 0x402, 3, "SPARE", "SPARES 5"),
            ("ND5FD99T5", 0x405, 11, "CHAR", "TAX AMOUNT 5"),
            
            # Remaining 94 tax entries (94 x 16 = 1504 bytes)
            ("ND5FDTXS_REMAINING", 0x410, 1504, "CHAR", "REMAINING REFUND TAXES (94x16)"),
            
            # Tax Surcharge Data (99 x 5 bytes each) - break down first few
            ("ND5FDOBT1", 0x9F0, 2, "CHAR", "FEE CODE 1"),
            ("ND5FDOBS1", 0x9F2, 3, "CHAR", "FEE SUBCODE 1"),
            
            ("ND5FDOBT2", 0x9F5, 2, "CHAR", "FEE CODE 2"),
            ("ND5FDOBS2", 0x9F7, 3, "CHAR", "FEE SUBCODE 2"),
            
            ("ND5FDOBT3", 0x9FA, 2, "CHAR", "FEE CODE 3"),
            ("ND5FDOBS3", 0x9FC, 3, "CHAR", "FEE SUBCODE 3"),
            
            # Remaining 96 surcharge entries (96 x 5 = 480 bytes)
            ("ND5FDOBA_REMAINING", 0x9FF, 480, "CHAR", "REMAINING TAX SURCHARGE DATA (96x5)"),
            
            ("ND5FDRPE", 0xBDF, 32, "CHAR", "PAYMENT REFERENCE ID"),
        ]

        # Variable length data items structure (ND5FDITM)
        # Used by both TAR records (at ND5FDTDF offset) and PAR records (at ND5FDMDI offset)
        self.variable_data_item_fields = [
            ("ND5FDTID", 0x000, 1, "BIT", "Data Item Type - ID"),
            ("ND5FDTCT", 0x001, 2, "BIN", "Byte count of this data item"),
            ("ND5FDVTD", 0x003, 1, "CHAR", "Start of Variable Length Text (1-1400 bytes)"),
        ]

    def get_variable_data_offset(self, record_type):
        """Get the offset where variable length data items start"""
        if record_type in ["TAR", "NBT"]:
            return 0x060 + 0x088  # TAR structure + ND5FDTDF offset
        elif record_type == "PAR":
            return 0x060 + 0x370  # MAR structure + ND5FDMDI offset
        else:
            return None  # No variable data for other record types


    def parse_displaced_input(self, input_data):
        """Parse input data with displacement offsets"""
        data_dict = {}
        lines = input_data.strip().split('\n')
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
                
            # Handle format with displayable text: "000 D5FD0000 C2C1C3C1 00000000 00000000 ** N   BACA        ¬"
            # Split by '**' and take only the hex part
            if '**' in line:
                line = line.split('**')[0].strip()
                
            # Parse format: "000 D5FD0000 C2C1C3C1 00000000 00000000"
            parts = line.split()
            if len(parts) < 2:
                continue
                
            try:
                offset = int(parts[0], 16)  # Convert hex offset to int
                hex_data = ''.join(parts[1:])  # Join all hex parts
                
                # Skip lines with all zeros
                if hex_data.replace('0', '') == '':
                    continue
                    
                data_dict[offset] = hex_data
            except ValueError:
                continue
        
        # Build continuous byte array
        if not data_dict:
            return b''
            
        max_offset = max(data_dict.keys())
        result = bytearray(max_offset + len(bytes.fromhex(data_dict[max_offset])))
        
        for offset, hex_data in data_dict.items():
            try:
                data_bytes = bytes.fromhex(hex_data)
                result[offset:offset + len(data_bytes)] = data_bytes
            except ValueError:
                continue
                
        return bytes(result)

    def hex_to_bytes(self, hex_string):
        # Check if input has displacement format
        if any(line.strip().split()[0].isdigit() or 
               any(c in line.strip().split()[0] for c in 'ABCDEF') 
               for line in hex_string.split('\n') if line.strip()):
            return self.parse_displaced_input(hex_string)
        else:
            hex_clean = hex_string.replace(' ', '').replace('\n', '')
            return bytes.fromhex(hex_clean)

    def ebcdic_to_ascii(self, data):
        try:
            return codecs.decode(data, 'cp037', errors='replace').rstrip('\x00').rstrip(' ')
        except:
            return data.hex().upper()

    def format_value(self, field_data, field_type):
        if field_type == "CHAR":
            return self.ebcdic_to_ascii(field_data)
        elif field_type == "BIN":
            return str(int.from_bytes(field_data, 'big'))
        elif field_type == "PIC":
            return self.ebcdic_to_ascii(field_data)
        elif field_type == "BIT":
            return field_data.hex().upper()
        elif field_type == "SPARE":
            return "(SPARE)"
        else:
            return field_data.hex().upper()

    def is_blank_field(self, field_data):
        """Check if field contains all EBCDIC spaces (0x40)"""
        return all(byte == 0x40 for byte in field_data)

    def is_blank_or_zero_field(self, field_data):
        """Check if field contains all EBCDIC spaces (0x40) or all zeros"""
        return (all(byte == 0x40 for byte in field_data) or 
                all(byte == 0x00 for byte in field_data))

    def get_record_type(self, data):
        if len(data) > 0x022:
            type_data = data[0x020:0x023]
            return self.ebcdic_to_ascii(type_data).strip()
        return "UNK"

    def parse_variable_data_items(self, data, start_offset, output_file):
        """Parse variable length data items (ND5FDITM)"""
        if start_offset >= len(data):
            return
        
        # Data item type mappings from D5FD.h (decimal values)
        data_item_types = {
            1: ("Transmission Control Number", "Control number for transmission"),
            2: ("Passenger Name", "Name of the passenger"),
            4: ("Group or Convention Name", "Group or convention identifier"),
            6: ("Name Remarks", "Additional name information"),
            8: ("Telephone Number", "Contact telephone number"),
            10: ("TBM Mailing Address", "Ticket-by-mail mailing address"),
            12: ("TBM Billing Address", "Ticket-by-mail billing address"),
            14: ("Date Ticket Mailed", "Date ticket was mailed"),
            16: ("Frequent Flyer Number", "Loyalty program number"),
            20: ("Reprinted Ticket Numbers", "Numbers of reprinted tickets"),
            22: ("Form of Payment", "Payment method details"),
            24: ("Count of Psgrs Associated With FOP", "Number of passengers for this payment"),
            25: ("Equivalent Fare Paid Decimal Indicator", "Decimal position indicator"),
            26: ("Equivalent Fare Paid", "Equivalent fare amount"),
            28: ("Equivalent Fare Paid Currency Code", "Currency for equivalent fare"),
            29: ("Tkt/Doc Effective Date", "Document effective date"),
            30: ("Tkt/Doc Expiration Date", "Document expiration date"),
            31: ("Booking Class Limitation", "Class restrictions"),
            32: ("Approval Code", "Payment approval code"),
            36: ("Tour Code", "Tour package identifier"),
            38: ("Number of Tickets Exchanged", "Count of exchanged tickets"),
            39: ("Exchanged Ticket Value Decimal Indicator", "Decimal position for exchange value"),
            40: ("Issued in Exchange for Ticket Number", "Original ticket number"),
            42: ("Issued in Exchange for Coupon Numbers", "Original coupon numbers"),
            44: ("Value of Exchanged Ticket", "Monetary value of exchange"),
            46: ("Original Issue Ticket Number", "First issue ticket number"),
            48: ("Date of Original Issue", "Original issue date"),
            50: ("Place of Original Issue", "Original issue location"),
            52: ("Form of Payment of Exchanged Ticket(s)", "Payment method for exchanged tickets"),
            54: ("Exchanged Ticket Currency Code", "Currency for exchanged tickets"),
            56: ("ATC/IATA Number", "Agent/airline identifier"),
            58: ("Commission Rate", "Agent commission percentage"),
            60: ("Total Amount Adjusted", "Total adjustment amount"),
            61: ("PTA Amounts Decimal Indicator", "PTA decimal position"),
            62: ("Count of MCO Numbers", "Number of MCO documents"),
            64: ("MCO Number", "Miscellaneous charges order number"),
            66: ("Original Fare Currency Code", "Original fare currency"),
            68: ("Original PTA Total", "Original PTA amount"),
            70: ("FOP of Each PTA", "Form of payment for each PTA"),
            71: ("REPS DATA", "Credit card processing data"),
            72: ("Fare Calculation", "Fare calculation details"),
            74: ("Itinerary Segment Data", "Flight segment information"),
            76: ("Fare Basis", "Fare basis code"),
            78: ("Connecting/Stopover Code", "Connection/stopover indicator"),
            80: ("Validity Dates", "Ticket validity dates"),
            82: ("Seat Assignment", "Assigned seat information"),
            84: ("Baggage Allowance", "Baggage allowance details"),
            86: ("Endorsement Box/Penalty", "Endorsement and penalty information"),
            88: ("Commission Amount", "Commission amount"),
            89: ("Booking Class/Date", "Booking class and date"),
            90: ("Reissue Tax Breakdown", "Tax breakdown for reissue"),
            93: ("Reissue PFC Breakdown", "PFC breakdown for reissue"),
            94: ("Tax Surcharge Data", "Fee information for Global Collect"),
            95: ("Document Taxes", "Document tax information"),
            96: ("GTO Commission Rate", "GTO commission rate"),
            97: ("GTO Commission Amount", "GTO commission amount"),
            200: ("Servicing Carrier Accounting Code", "ARC servicing carrier code"),
            202: ("Servicing Carrier Guarantee Code", "ARC guarantee code"),
            204: ("Agency Number (ATC/IATA)", "ARC agency number"),
            206: ("Agency Number Check Digit", "ARC agency check digit"),
            208: ("Credit Card Contractor Number", "ARC credit card contractor"),
            210: ("Commission Rate", "ARC commission rate"),
            212: ("Commission Amount", "ARC commission amount"),
            214: ("Tax Code (Future)", "ARC future tax code"),
            216: ("Ticketing Carrier Accounting Code", "ARC ticketing carrier code"),
            218: ("Domestic/International Code", "ARC domestic/international indicator"),
            220: ("Self-Sale Code", "ARC self-sale code"),
        }
        
        config = self.get_header_config()
        output_file.write("\n" + "=" * config["sep_width"] + "\n")
        output_file.write("VARIABLE LENGTH DATA ITEMS (ND5FDITM)\n")
        output_file.write("=" * config["sep_width"] + "\n")

        current_offset = start_offset
        item_count = 0

        while current_offset < len(data) - 2:
            # Read type ID (1 byte)
            type_id = data[current_offset]
            
            # Check for end marker (4E)
            if type_id == 0x4E:
                output_file.write(f"\nEnd marker found at offset {current_offset:04X}h\n")
                break
                
            # Skip if we hit zero padding
            if type_id == 0:
                current_offset += 1
                continue
                
            # Read total length (2 bytes, big-endian) - includes type + length + data
            if current_offset + 3 > len(data):
                break
                
            total_length = int.from_bytes(data[current_offset + 1:current_offset + 3], 'big')
            
            if total_length < 3 or current_offset + total_length > len(data):
                break
            
            # Data length = total length - 3 (1 byte type + 2 bytes length)
            data_length = total_length - 3
            
            item_count += 1
            type_name, description = data_item_types.get(type_id, ("Unknown Type", "Unknown data item"))
            
            output_file.write(f"\nData Item #{item_count}:\n")
            output_file.write(f"  Offset:       {current_offset:04X}h\n")
            output_file.write(f"  Type ID:      {type_id:02X}h ({type_id} decimal)\n")
            output_file.write(f"  Name:         {type_name}\n")
            output_file.write(f"  Total Length: {total_length} bytes\n")
            output_file.write(f"  Data Length:  {data_length} bytes\n")
            output_file.write(f"  Description:  {description}\n")
        
            if data_length > 0:
                item_data = data[current_offset + 3:current_offset + 3 + data_length]
                hex_value = item_data.hex().upper()
                ascii_value = self.ebcdic_to_ascii(item_data)
                output_file.write(f"  Data:         {hex_value}\n")
                output_file.write(f"  ASCII:        {ascii_value}\n")
        
            # Move to next item using total length
            current_offset += total_length
        
            if item_count >= 30:
                output_file.write("  ... (truncated after 30 items)\n")
                break

    def get_header_config(self):
        configs = {
            "small": {"sep_width": 40, "table_width": 60, "hex_width": 16, "value_width": 15},
            "normal": {"sep_width": 80, "table_width": 120, "hex_width": 32, "value_width": 30},
            "large": {"sep_width": 120, "table_width": 160, "hex_width": 40, "value_width": 35}
        }
        return configs.get(self.header_size, configs["normal"])

    def parse_header(self, data, output_file):
        config = self.get_header_config()
        output_file.write("=" * config["sep_width"] + "\n")
        output_file.write("HEADER FIELDS\n")
        output_file.write("=" * config["sep_width"] + "\n")
        output_file.write(f"{'Field Name':<12} {'Offset':<8} {'Length':<8} {'HEX Value':<{config['hex_width']}} {'Value':<{config['value_width']}} {'Description'}\n")
        output_file.write("-" * config["table_width"] + "\n")

        for field_name, offset, length, field_type, description in self.header_fields:
            if offset + length <= len(data):
                field_data = data[offset:offset + length]
                hex_value = field_data.hex().upper()
                formatted_value = self.format_value(field_data, field_type)
                output_file.write(f"{field_name:<12} {offset:04X}h    {length:<8} {hex_value:<{config['hex_width']}} {formatted_value:<{config['value_width']}} {description}\n")


    def parse_bti_structure(self, data, record_type, output_file):
        config = self.get_header_config()
        bti_offset = 0x060
        
        output_file.write("\n" + "=" * config["sep_width"] + "\n")
        output_file.write(f"ND5FDBTI STRUCTURE - TYPE: {record_type}\n")
        output_file.write("=" * config["sep_width"] + "\n")
        output_file.write(f"{'Field Name':<12} {'Offset':<8} {'Length':<8} {'HEX Value':<{config['hex_width']}} {'Value':<{config['value_width']}} {'Description'}\n")
        output_file.write("-" * config["table_width"] + "\n")

        if record_type in ["TAR", "NBT"]:
            fields = self.tar_fields
            output_file.write("Using TAR (Ticket Accounting Record) structure\n")
        elif record_type == "REF":
            fields = self.ref_fields
            output_file.write("Using REF (Refund) structure\n")
        elif record_type == "MAR":
            fields = self.mir_fields
            output_file.write("Using MIR (Miscellaneous Transaction Data) structure\n")
        elif record_type == "PAR":
            fields = self.mar_fields
            output_file.write("Using MAR (Prepaid Accounting Data) structure\n")
        elif record_type == "VOI":
            fields = self.voi_fields
            output_file.write("Using VOI (Void Transaction) structure\n")
        elif record_type == "ATR":
            fields = self.atr_fields
            output_file.write("Using ATR (Agent Transaction) structure\n")
        elif record_type in ["AIR", "VDC"]:
            fields = self.air_fields
            output_file.write("Using AIR (Additional Collection) structure\n")
        elif record_type == "IFR":
            fields = self.ifr_fields
            output_file.write("Using IFR (In-Flight Sales) structure\n")
        elif record_type == "BOW":
            fields = self.bow_fields
            output_file.write("Using BOW (List Transaction Data) structure\n")
        elif record_type in ["COL", "CRR"]:
            fields = self.col_fields
            output_file.write("Using COL (Collection Report) structure\n")
        else:
            output_file.write(f"Unknown record type: {record_type}, using generic parsing\n")
            if len(data) > bti_offset:
                raw_data = data[bti_offset:bti_offset + min(100, len(data) - bti_offset)]
                output_file.write(f"Raw BTI Data: {raw_data.hex().upper()}\n")
            return
        
        output_file.write("-" * config["table_width"] + "\n")
        
        for field_name, rel_offset, length, field_type, description in fields:
            abs_offset = bti_offset + rel_offset
            if abs_offset + length <= len(data):
                field_data = data[abs_offset:abs_offset + length]
                if self.is_blank_or_zero_field(field_data):
                    continue
                hex_value = field_data.hex().upper()
                formatted_value = self.format_value(field_data, field_type)
                output_file.write(f"{field_name:<12} {abs_offset:04X}h    {length:<8} {hex_value:<{config['hex_width']}} {formatted_value:<{config['value_width']}} {description}\n")

        # Parse variable length data items for TAR and PAR records
        variable_offset = self.get_variable_data_offset(record_type)
        if variable_offset and variable_offset < len(data):
            self.parse_variable_data_items(data, variable_offset, output_file)

    def parse_record_to_file(self, hex_input, output_file):
        try:
            data = self.hex_to_bytes(hex_input)
            
            output_file.write("D5FD Enhanced Record Parser Results\n")
            output_file.write(f"Total Data Length: {len(data)} bytes\n\n")
            
            self.parse_header(data, output_file)
            record_type = self.get_record_type(data)
            self.parse_bti_structure(data, record_type, output_file)
            
            config = self.get_header_config()
            output_file.write("\n" + "=" * config["sep_width"] + "\n")
            
        except Exception as e:
            output_file.write(f"Error parsing record: {e}\n")

def main():
    # Default file names
    input_file = "input.txt"
    output_file = "output.txt"
    header_size = "small"  # Default header size
    
    # Check if custom file names provided as arguments
    if len(sys.argv) >= 3:
        input_file = sys.argv[1]
        output_file = sys.argv[2]
    if len(sys.argv) >= 4:
        header_size = sys.argv[3]  # small, normal, or large
    
    parser = D5FDFileParser(header_size)
    
    try:
        # Read input file
        if not os.path.exists(input_file):
            print(f"Error: Input file '{input_file}' not found!")
            print("Usage: py d5fd_file_parser.py [input_file] [output_file]")
            print("Default: py d5fd_file_parser.py (uses input.txt and output.txt)")
            return
        
        with open(input_file, 'r') as f:
            hex_data = f.read().strip()
        
        # Parse and write to output file
        with open(output_file, 'w', encoding='utf-8') as f:
            parser.parse_record_to_file(hex_data, f)
        
        print(f"Parsing completed!")
        print(f"Input file: {input_file}")
        print(f"Output file: {output_file}")
        
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
