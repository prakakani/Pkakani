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
    def __init__(self):
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
        ]
        
        # MAR structure fields (ND5FDMAR) - offset from 0x060
        self.mar_fields = [
            ("SPARE_MAR1", 0x000, 2, "SPARE", "SPARES"),
            ("ND5FDMCI", 0x002, 3, "CHAR", "TICKETING CITY"),
            ("SPARE_MAR2", 0x005, 3, "SPARE", "SPARES"),
            ("ND5FDMTG", 0x008, 2, "CHAR", "TICKETING TELETYPE ADDRESS"),
            ("ND5FDMAL", 0x00A, 2, "CHAR", "TICKETING AIRLINE"),
            ("SPARE_MAR3", 0x00C, 2, "SPARE", "SPARES"),
            ("ND5FDMNS", 0x00E, 29, "CHAR", "PASSENGER NAME 1"),
            ("ND5FDMNS2", 0x02B, 29, "CHAR", "PASSENGER NAME 2"),
            ("SPARE_MAR4", 0x048, 2, "SPARE", "SPARES"),
            ("ND5FDMMN", 0x04A, 14, "CHAR", "MCO NUMBER"),
            ("ND5FDMDN", 0x058, 1, "CHAR", "DUPE MCO NBR INDICATOR"),
            ("SPARE_MAR5", 0x059, 1, "SPARE", "SPARE"),
            ("ND5FDMON", 0x05A, 14, "CHAR", "OLD MCO NUMBER"),
            ("SPARE_MAR6", 0x068, 2, "SPARE", "SPARES"),
            ("ND5FDMID", 0x06A, 7, "CHAR", "ISSUE DATE"),
            ("SPARE_MAR7", 0x071, 1, "SPARE", "SPARE"),
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
            ("ND5FDMBC", 0x0A6, 3, "CHAR", "BASE FARE CURRENCY CODE"),
            ("SPARE_MAR14", 0x0A9, 1, "SPARE", "SPARE"),
            ("ND5FDMBI", 0x0AA, 1, "CHAR", "BASE FARE DECIMAL INDICATOR"),
            ("SPARE_MAR15", 0x0AB, 1, "SPARE", "SPARE"),
            ("ND5FDMBA", 0x0AC, 8, "PIC", "FARE AMOUNT"),
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
        ]

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
            16: ("Frequent Flyer Number", "Loyalty program number"),
            32: ("Reprinted Ticket Numbers", "Numbers of reprinted tickets"),
            34: ("Form of Payment", "Payment method details"),
            36: ("Count of Psgrs Associated With FOP", "Number of passengers for this payment"),
            37: ("Equivalent Fare Paid Decimal Indicator", "Decimal position indicator"),
            38: ("Equivalent Fare Paid", "Equivalent fare amount"),
            40: ("Equivalent Fare Paid Currency Code", "Currency for equivalent fare"),
            41: ("Tkt/Doc Effective Date", "Document effective date"),
            48: ("Tkt/Doc Expiration Date", "Document expiration date"),
            49: ("Booking Class Limitation", "Class restrictions"),
            50: ("Approval Code", "Payment approval code"),
            54: ("Tour Code", "Tour package identifier"),
            56: ("Number of Tickets Exchanged", "Count of exchanged tickets"),
            57: ("Exchanged Ticket Value Decimal Indicator", "Decimal position for exchange value"),
            64: ("Issued in Exchange for Ticket Number", "Original ticket number"),
            66: ("Issued in Exchange for Coupon Numbers", "Original coupon numbers"),
            68: ("Value of Exchanged Ticket", "Monetary value of exchange"),
            70: ("Original Issue Ticket Number", "First issue ticket number"),
            72: ("Date of Original Issue", "Original issue date"),
            80: ("Place of Original Issue", "Original issue location"),
            82: ("Form of Payment of Exchanged Ticket(s)", "Payment method for exchanged tickets"),
            84: ("Exchanged Ticket Currency Code", "Currency for exchanged tickets"),
            86: ("ATC/IATA Number", "Agent/airline identifier"),
            88: ("Commission Rate", "Agent commission percentage"),
            96: ("Total Amount Adjusted", "Total adjustment amount"),
            97: ("PTA Amounts Decimal Indicator", "PTA decimal position"),
            98: ("Count of MCO Numbers", "Number of MCO documents"),
            100: ("MCO Number", "Miscellaneous charges order number"),
            102: ("Original Fare Currency Code", "Original fare currency"),
            104: ("Original PTA Total", "Original PTA amount"),
            112: ("FOP of Each PTA", "Form of payment for each PTA"),
            113: ("REPS DATA", "Credit card processing data"),
        }
        
        output_file.write("\n" + "=" * 80 + "\n")
        output_file.write("VARIABLE LENGTH DATA ITEMS (ND5FDITM)\n")
        output_file.write("=" * 80 + "\n")
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
        
            if item_count >= 20:
                output_file.write("  ... (truncated after 20 items)\n")
                break
                
    def parse_header(self, data, output_file):
        output_file.write("=" * 80 + "\n")
        output_file.write("HEADER FIELDS\n")
        output_file.write("=" * 80 + "\n")
        output_file.write(f"{'Field Name':<12} {'Offset':<8} {'Length':<8} {'HEX Value':<32} {'Value':<30} {'Description'}\n")
        output_file.write("-" * 120 + "\n")
        
        for field_name, offset, length, field_type, description in self.header_fields:
            if offset + length <= len(data):
                field_data = data[offset:offset + length]
                hex_value = field_data.hex().upper()
                formatted_value = self.format_value(field_data, field_type)
                output_file.write(f"{field_name:<12} {offset:04X}h    {length:<8} {hex_value:<32} {formatted_value:<30} {description}\n")

    def parse_bti_structure(self, data, record_type, output_file):
        bti_offset = 0x060
        
        output_file.write("\n" + "=" * 80 + "\n")
        output_file.write(f"ND5FDBTI STRUCTURE - TYPE: {record_type}\n")
        output_file.write("=" * 80 + "\n")
        output_file.write(f"{'Field Name':<12} {'Offset':<8} {'Length':<8} {'HEX Value':<32} {'Value':<30} {'Description'}\n")
        output_file.write("-" * 120 + "\n")
        
        if record_type in ["TAR", "NBT"]:
            fields = self.tar_fields
            output_file.write("Using TAR (Ticket Accounting Record) structure\n")
        elif record_type == "REF":
            fields = self.ref_fields
            output_file.write("Using REF (Refund) structure\n")
        elif record_type in ["MAR", "PAR"]:
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
        
        output_file.write("-" * 120 + "\n")
        
        for field_name, rel_offset, length, field_type, description in fields:
            abs_offset = bti_offset + rel_offset
            if abs_offset + length <= len(data):
                field_data = data[abs_offset:abs_offset + length]
                if self.is_blank_field(field_data):
                    continue
                hex_value = field_data.hex().upper()
                formatted_value = self.format_value(field_data, field_type)
                output_file.write(f"{field_name:<12} {abs_offset:04X}h    {length:<8} {hex_value:<32} {formatted_value:<30} {description}\n")
                
        # Parse variable length data items for TAR records
        if record_type in ["TAR", "NBT"]:
            var_data_offset = 0xE8  # Start of variable data
            self.parse_variable_data_items(data, var_data_offset, output_file)
            
    def parse_record_to_file(self, hex_input, output_file):
        try:
            data = self.hex_to_bytes(hex_input)
            
            output_file.write("D5FD Enhanced Record Parser Results\n")
            output_file.write(f"Total Data Length: {len(data)} bytes\n\n")
            
            self.parse_header(data, output_file)
            record_type = self.get_record_type(data)
            self.parse_bti_structure(data, record_type, output_file)
            
            output_file.write("\n" + "=" * 80 + "\n")
            
        except Exception as e:
            output_file.write(f"Error parsing record: {e}\n")

def main():
    # Default file names
    input_file = "input.txt"
    output_file = "output.txt"
    
    # Check if custom file names provided as arguments
    if len(sys.argv) >= 3:
        input_file = sys.argv[1]
        output_file = sys.argv[2]
    
    parser = D5FDFileParser()
    
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
