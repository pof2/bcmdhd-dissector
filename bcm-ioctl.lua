-- Copyright (C) 2014 Pontus Fuchs (pontus.fuchs@gmail.com)
--
-- This program is free software; you can redistribute it and/or
-- modify it under the terms of the GNU General Public License
-- as published by the Free Software Foundation; either version 2
-- of the License, or (at your option) any later version.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License
-- along with this program; if not, write to the Free Software
-- Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

local bit = require("bit")
local bcm = Proto("bcmioctl", "BCM WLAN dissector- IOCTLs")
local f = bcm.fields
local cdc_ioctl_cmd_strings = {}

function bcm.init()
	local udp_table = DissectorTable.get("ethertype")
	local pattern = 0xBC02
	udp_table:add(pattern, bcm)
end


function bcm.dissector(inbuffer, pinfo, tree)
	local n = 0
	local buffer = inbuffer
	pinfo.cols.protocol = "bcm-ioctl"
	pinfo.cols.info = ""

	local cmd = buffer(0, 4):le_uint();

	local subtree = tree:add(bcm, buffer(), "BCM IOCTL")
	local header = subtree:add(bcm, buffer(n, 8), "header")

	header:add_le(f.bcm_cdc_ioctl_cmd, buffer(n, 4)); n = n + 4
	header:add_le(f.bcm_cdc_ioctl_len, buffer(n, 4)); n = n + 4
	header:add_le(f.bcm_cdc_ioctl_flags, buffer(n, 4)); n = n + 4
	header:add_le(f.bcm_cdc_ioctl_status, buffer(n, 4)); n = n + 4

	local cmd_str
	if cdc_ioctl_cmd_strings[cmd] ~= nil then
		cmd_str = cdc_ioctl_cmd_strings[cmd]:lower()
	else
		cmd_str = cmd
	end
	pinfo.cols.info:append(cmd_str)

	-- data
	if buffer:len() > n then
		local par = subtree:add(bcm, buffer(n), cmd_str)

		if (cmd == 262) then
			-- WLC_GET_VAR
			pinfo.cols.info:append(" "..buffer(n):stringz())
			par:add(f.bcm_var_name, buffer(n)); n = n + buffer(n):stringz():len() + 1
		elseif (cmd == 263) then
			-- WLC_SET_VAR
			pinfo.cols.info:append(" "..buffer(n):stringz())
			par:add(f.bcm_var_name,  buffer(n)); n = n + buffer(n):stringz():len() + 1
			end

		-- add data not parsed above
		if (buffer:len() > n) then
			par:add(f.data, buffer(n))
		end

	end
end

cdc_ioctl_cmd_strings[0] = "WLC_GET_MAGIC"
cdc_ioctl_cmd_strings[1] = "WLC_GET_VERSION"
cdc_ioctl_cmd_strings[2] = "WLC_UP"
cdc_ioctl_cmd_strings[3] = "WLC_DOWN"
cdc_ioctl_cmd_strings[4] = "WLC_GET_LOOP"
cdc_ioctl_cmd_strings[5] = "WLC_SET_LOOP"
cdc_ioctl_cmd_strings[6] = "WLC_DUMP"
cdc_ioctl_cmd_strings[7] = "WLC_GET_MSGLEVEL"
cdc_ioctl_cmd_strings[8] = "WLC_SET_MSGLEVEL"
cdc_ioctl_cmd_strings[9] = "WLC_GET_PROMISC"
cdc_ioctl_cmd_strings[10] = "WLC_SET_PROMISC"
cdc_ioctl_cmd_strings[11] = "WLC_OVERLAY_IOCTL"
cdc_ioctl_cmd_strings[12] = "WLC_GET_RATE"
cdc_ioctl_cmd_strings[13] = "WLC_GET_MAX_RATE"
cdc_ioctl_cmd_strings[14] = "WLC_GET_INSTANCE"
cdc_ioctl_cmd_strings[15] = "WLC_GET_FRAG"
cdc_ioctl_cmd_strings[16] = "WLC_SET_FRAG"
cdc_ioctl_cmd_strings[17] = "WLC_GET_RTS"
cdc_ioctl_cmd_strings[18] = "WLC_SET_RTS"
cdc_ioctl_cmd_strings[19] = "WLC_GET_INFRA"
cdc_ioctl_cmd_strings[20] = "WLC_SET_INFRA"
cdc_ioctl_cmd_strings[21] = "WLC_GET_AUTH"
cdc_ioctl_cmd_strings[22] = "WLC_SET_AUTH"
cdc_ioctl_cmd_strings[23] = "WLC_GET_BSSID"
cdc_ioctl_cmd_strings[24] = "WLC_SET_BSSID"
cdc_ioctl_cmd_strings[25] = "WLC_GET_SSID"
cdc_ioctl_cmd_strings[26] = "WLC_SET_SSID"
cdc_ioctl_cmd_strings[27] = "WLC_RESTART"
cdc_ioctl_cmd_strings[28] = "WLC_TERMINATED"
cdc_ioctl_cmd_strings[28] = "WLC_DUMP_SCB"
cdc_ioctl_cmd_strings[29] = "WLC_GET_CHANNEL"
cdc_ioctl_cmd_strings[30] = "WLC_SET_CHANNEL"
cdc_ioctl_cmd_strings[31] = "WLC_GET_SRL"
cdc_ioctl_cmd_strings[32] = "WLC_SET_SRL"
cdc_ioctl_cmd_strings[33] = "WLC_GET_LRL"
cdc_ioctl_cmd_strings[34] = "WLC_SET_LRL"
cdc_ioctl_cmd_strings[35] = "WLC_GET_PLCPHDR"
cdc_ioctl_cmd_strings[36] = "WLC_SET_PLCPHDR"
cdc_ioctl_cmd_strings[37] = "WLC_GET_RADIO"
cdc_ioctl_cmd_strings[38] = "WLC_SET_RADIO"
cdc_ioctl_cmd_strings[39] = "WLC_GET_PHYTYPE"
cdc_ioctl_cmd_strings[40] = "WLC_DUMP_RATE"
cdc_ioctl_cmd_strings[41] = "WLC_SET_RATE_PARAMS"
cdc_ioctl_cmd_strings[42] = "WLC_GET_FIXRATE"
cdc_ioctl_cmd_strings[43] = "WLC_SET_FIXRATE"
cdc_ioctl_cmd_strings[42] = "WLC_GET_WEP"
cdc_ioctl_cmd_strings[43] = "WLC_SET_WEP"
cdc_ioctl_cmd_strings[44] = "WLC_GET_KEY"
cdc_ioctl_cmd_strings[45] = "WLC_SET_KEY"
cdc_ioctl_cmd_strings[46] = "WLC_GET_REGULATORY"
cdc_ioctl_cmd_strings[47] = "WLC_SET_REGULATORY"
cdc_ioctl_cmd_strings[48] = "WLC_GET_PASSIVE_SCAN"
cdc_ioctl_cmd_strings[49] = "WLC_SET_PASSIVE_SCAN"
cdc_ioctl_cmd_strings[50] = "WLC_SCAN"
cdc_ioctl_cmd_strings[51] = "WLC_SCAN_RESULTS"
cdc_ioctl_cmd_strings[52] = "WLC_DISASSOC"
cdc_ioctl_cmd_strings[53] = "WLC_REASSOC"
cdc_ioctl_cmd_strings[54] = "WLC_GET_ROAM_TRIGGER"
cdc_ioctl_cmd_strings[55] = "WLC_SET_ROAM_TRIGGER"
cdc_ioctl_cmd_strings[56] = "WLC_GET_ROAM_DELTA"
cdc_ioctl_cmd_strings[57] = "WLC_SET_ROAM_DELTA"
cdc_ioctl_cmd_strings[58] = "WLC_GET_ROAM_SCAN_PERIOD"
cdc_ioctl_cmd_strings[59] = "WLC_SET_ROAM_SCAN_PERIOD"
cdc_ioctl_cmd_strings[60] = "WLC_EVM"
cdc_ioctl_cmd_strings[61] = "WLC_GET_TXANT"
cdc_ioctl_cmd_strings[62] = "WLC_SET_TXANT"
cdc_ioctl_cmd_strings[63] = "WLC_GET_ANTDIV"
cdc_ioctl_cmd_strings[64] = "WLC_SET_ANTDIV"
cdc_ioctl_cmd_strings[65] = "WLC_GET_TXPWR"
cdc_ioctl_cmd_strings[66] = "WLC_SET_TXPWR"
cdc_ioctl_cmd_strings[67] = "WLC_GET_CLOSED"
cdc_ioctl_cmd_strings[68] = "WLC_SET_CLOSED"
cdc_ioctl_cmd_strings[69] = "WLC_GET_MACLIST"
cdc_ioctl_cmd_strings[70] = "WLC_SET_MACLIST"
cdc_ioctl_cmd_strings[71] = "WLC_GET_RATESET"
cdc_ioctl_cmd_strings[72] = "WLC_SET_RATESET"
cdc_ioctl_cmd_strings[73] = "WLC_GET_LOCALE"
cdc_ioctl_cmd_strings[74] = "WLC_LONGTRAIN"
cdc_ioctl_cmd_strings[75] = "WLC_GET_BCNPRD"
cdc_ioctl_cmd_strings[76] = "WLC_SET_BCNPRD"
cdc_ioctl_cmd_strings[77] = "WLC_GET_DTIMPRD"
cdc_ioctl_cmd_strings[78] = "WLC_SET_DTIMPRD"
cdc_ioctl_cmd_strings[79] = "WLC_GET_SROM"
cdc_ioctl_cmd_strings[80] = "WLC_SET_SROM"
cdc_ioctl_cmd_strings[81] = "WLC_GET_WEP_RESTRICT"
cdc_ioctl_cmd_strings[82] = "WLC_SET_WEP_RESTRICT"
cdc_ioctl_cmd_strings[83] = "WLC_GET_COUNTRY"
cdc_ioctl_cmd_strings[84] = "WLC_SET_COUNTRY"
cdc_ioctl_cmd_strings[85] = "WLC_GET_PM"
cdc_ioctl_cmd_strings[86] = "WLC_SET_PM"
cdc_ioctl_cmd_strings[87] = "WLC_GET_WAKE"
cdc_ioctl_cmd_strings[88] = "WLC_SET_WAKE"
cdc_ioctl_cmd_strings[89] = "WLC_GET_D11CNTS"
cdc_ioctl_cmd_strings[90] = "WLC_GET_FORCELINK"
cdc_ioctl_cmd_strings[91] = "WLC_SET_FORCELINK"
cdc_ioctl_cmd_strings[92] = "WLC_FREQ_ACCURACY"
cdc_ioctl_cmd_strings[93] = "WLC_CARRIER_SUPPRESS"
cdc_ioctl_cmd_strings[94] = "WLC_GET_PHYREG"
cdc_ioctl_cmd_strings[95] = "WLC_SET_PHYREG"
cdc_ioctl_cmd_strings[96] = "WLC_GET_RADIOREG"
cdc_ioctl_cmd_strings[97] = "WLC_SET_RADIOREG"
cdc_ioctl_cmd_strings[98] = "WLC_GET_REVINFO"
cdc_ioctl_cmd_strings[99] = "WLC_GET_UCANTDIV"
cdc_ioctl_cmd_strings[100] = "WLC_SET_UCANTDIV"
cdc_ioctl_cmd_strings[101] = "WLC_R_REG"
cdc_ioctl_cmd_strings[102] = "WLC_W_REG"
cdc_ioctl_cmd_strings[103] = "WLC_DIAG_LOOPBACK"
cdc_ioctl_cmd_strings[104] = "WLC_RESET_D11CNTS"
cdc_ioctl_cmd_strings[105] = "WLC_GET_MACMODE"
cdc_ioctl_cmd_strings[106] = "WLC_SET_MACMODE"
cdc_ioctl_cmd_strings[107] = "WLC_GET_MONITOR"
cdc_ioctl_cmd_strings[108] = "WLC_SET_MONITOR"
cdc_ioctl_cmd_strings[109] = "WLC_GET_GMODE"
cdc_ioctl_cmd_strings[110] = "WLC_SET_GMODE"
cdc_ioctl_cmd_strings[111] = "WLC_GET_LEGACY_ERP"
cdc_ioctl_cmd_strings[112] = "WLC_SET_LEGACY_ERP"
cdc_ioctl_cmd_strings[113] = "WLC_GET_RX_ANT"
cdc_ioctl_cmd_strings[114] = "WLC_GET_CURR_RATESET"
cdc_ioctl_cmd_strings[115] = "WLC_GET_SCANSUPPRESS"
cdc_ioctl_cmd_strings[116] = "WLC_SET_SCANSUPPRESS"
cdc_ioctl_cmd_strings[117] = "WLC_GET_AP"
cdc_ioctl_cmd_strings[118] = "WLC_SET_AP"
cdc_ioctl_cmd_strings[119] = "WLC_GET_EAP_RESTRICT"
cdc_ioctl_cmd_strings[120] = "WLC_SET_EAP_RESTRICT"
cdc_ioctl_cmd_strings[121] = "WLC_SCB_AUTHORIZE"
cdc_ioctl_cmd_strings[122] = "WLC_SCB_DEAUTHORIZE"
cdc_ioctl_cmd_strings[123] = "WLC_GET_WDSLIST"
cdc_ioctl_cmd_strings[124] = "WLC_SET_WDSLIST"
cdc_ioctl_cmd_strings[125] = "WLC_GET_ATIM"
cdc_ioctl_cmd_strings[126] = "WLC_SET_ATIM"
cdc_ioctl_cmd_strings[127] = "WLC_GET_RSSI"
cdc_ioctl_cmd_strings[128] = "WLC_GET_PHYANTDIV"
cdc_ioctl_cmd_strings[129] = "WLC_SET_PHYANTDIV"
cdc_ioctl_cmd_strings[130] = "WLC_AP_RX_ONLY"
cdc_ioctl_cmd_strings[131] = "WLC_GET_TX_PATH_PWR"
cdc_ioctl_cmd_strings[132] = "WLC_SET_TX_PATH_PWR"
cdc_ioctl_cmd_strings[133] = "WLC_GET_WSEC"
cdc_ioctl_cmd_strings[134] = "WLC_SET_WSEC"
cdc_ioctl_cmd_strings[135] = "WLC_GET_PHY_NOISE"
cdc_ioctl_cmd_strings[136] = "WLC_GET_BSS_INFO"
cdc_ioctl_cmd_strings[137] = "WLC_GET_PKTCNTS"
cdc_ioctl_cmd_strings[138] = "WLC_GET_LAZYWDS"
cdc_ioctl_cmd_strings[139] = "WLC_SET_LAZYWDS"
cdc_ioctl_cmd_strings[140] = "WLC_GET_BANDLIST"
cdc_ioctl_cmd_strings[141] = "WLC_GET_BAND"
cdc_ioctl_cmd_strings[142] = "WLC_SET_BAND"
cdc_ioctl_cmd_strings[143] = "WLC_SCB_DEAUTHENTICATE"
cdc_ioctl_cmd_strings[144] = "WLC_GET_SHORTSLOT"
cdc_ioctl_cmd_strings[145] = "WLC_GET_SHORTSLOT_OVERRIDE"
cdc_ioctl_cmd_strings[146] = "WLC_SET_SHORTSLOT_OVERRIDE"
cdc_ioctl_cmd_strings[147] = "WLC_GET_SHORTSLOT_RESTRICT"
cdc_ioctl_cmd_strings[148] = "WLC_SET_SHORTSLOT_RESTRICT"
cdc_ioctl_cmd_strings[149] = "WLC_GET_GMODE_PROTECTION"
cdc_ioctl_cmd_strings[150] = "WLC_GET_GMODE_PROTECTION_OVERRIDE"
cdc_ioctl_cmd_strings[151] = "WLC_SET_GMODE_PROTECTION_OVERRIDE"
cdc_ioctl_cmd_strings[152] = "WLC_UPGRADE"
cdc_ioctl_cmd_strings[153] = "WLC_GET_MRATE"
cdc_ioctl_cmd_strings[154] = "WLC_SET_MRATE"
cdc_ioctl_cmd_strings[155] = "WLC_GET_IGNORE_BCNS"
cdc_ioctl_cmd_strings[156] = "WLC_SET_IGNORE_BCNS"
cdc_ioctl_cmd_strings[157] = "WLC_GET_SCB_TIMEOUT"
cdc_ioctl_cmd_strings[158] = "WLC_SET_SCB_TIMEOUT"
cdc_ioctl_cmd_strings[159] = "WLC_GET_ASSOCLIST"
cdc_ioctl_cmd_strings[160] = "WLC_GET_CLK"
cdc_ioctl_cmd_strings[161] = "WLC_SET_CLK"
cdc_ioctl_cmd_strings[162] = "WLC_GET_UP"
cdc_ioctl_cmd_strings[163] = "WLC_OUT"
cdc_ioctl_cmd_strings[164] = "WLC_GET_WPA_AUTH"
cdc_ioctl_cmd_strings[165] = "WLC_SET_WPA_AUTH"
cdc_ioctl_cmd_strings[166] = "WLC_GET_UCFLAGS"
cdc_ioctl_cmd_strings[167] = "WLC_SET_UCFLAGS"
cdc_ioctl_cmd_strings[168] = "WLC_GET_PWRIDX"
cdc_ioctl_cmd_strings[169] = "WLC_SET_PWRIDX"
cdc_ioctl_cmd_strings[170] = "WLC_GET_TSSI"
cdc_ioctl_cmd_strings[171] = "WLC_GET_SUP_RATESET_OVERRIDE"
cdc_ioctl_cmd_strings[172] = "WLC_SET_SUP_RATESET_OVERRIDE"
cdc_ioctl_cmd_strings[173] = "WLC_SET_FAST_TIMER"
cdc_ioctl_cmd_strings[174] = "WLC_GET_FAST_TIMER"
cdc_ioctl_cmd_strings[175] = "WLC_SET_SLOW_TIMER"
cdc_ioctl_cmd_strings[176] = "WLC_GET_SLOW_TIMER"
cdc_ioctl_cmd_strings[177] = "WLC_DUMP_PHYREGS"
cdc_ioctl_cmd_strings[178] = "WLC_GET_PROTECTION_CONTROL"
cdc_ioctl_cmd_strings[179] = "WLC_SET_PROTECTION_CONTROL"
cdc_ioctl_cmd_strings[180] = "WLC_GET_PHYLIST"
cdc_ioctl_cmd_strings[181] = "WLC_ENCRYPT_STRENGTH"
cdc_ioctl_cmd_strings[182] = "WLC_DECRYPT_STATUS"
cdc_ioctl_cmd_strings[183] = "WLC_GET_KEY_SEQ"
cdc_ioctl_cmd_strings[184] = "WLC_GET_SCAN_CHANNEL_TIME"
cdc_ioctl_cmd_strings[185] = "WLC_SET_SCAN_CHANNEL_TIME"
cdc_ioctl_cmd_strings[186] = "WLC_GET_SCAN_UNASSOC_TIME"
cdc_ioctl_cmd_strings[187] = "WLC_SET_SCAN_UNASSOC_TIME"
cdc_ioctl_cmd_strings[188] = "WLC_GET_SCAN_HOME_TIME"
cdc_ioctl_cmd_strings[189] = "WLC_SET_SCAN_HOME_TIME"
cdc_ioctl_cmd_strings[190] = "WLC_GET_SCAN_NPROBES"
cdc_ioctl_cmd_strings[191] = "WLC_SET_SCAN_NPROBES"
cdc_ioctl_cmd_strings[192] = "WLC_GET_PRB_RESP_TIMEOUT"
cdc_ioctl_cmd_strings[193] = "WLC_SET_PRB_RESP_TIMEOUT"
cdc_ioctl_cmd_strings[194] = "WLC_GET_ATTEN"
cdc_ioctl_cmd_strings[195] = "WLC_SET_ATTEN"
cdc_ioctl_cmd_strings[196] = "WLC_GET_SHMEM"
cdc_ioctl_cmd_strings[197] = "WLC_SET_SHMEM"
cdc_ioctl_cmd_strings[198] = "WLC_GET_GMODE_PROTECTION_CTS"
cdc_ioctl_cmd_strings[199] = "WLC_SET_GMODE_PROTECTION_CTS"
cdc_ioctl_cmd_strings[200] = "WLC_SET_WSEC_TEST"
cdc_ioctl_cmd_strings[201] = "WLC_SCB_DEAUTHENTICATE_FOR_REASON"
cdc_ioctl_cmd_strings[202] = "WLC_TKIP_COUNTERMEASURES"
cdc_ioctl_cmd_strings[203] = "WLC_GET_PIOMODE"
cdc_ioctl_cmd_strings[204] = "WLC_SET_PIOMODE"
cdc_ioctl_cmd_strings[205] = "WLC_SET_ASSOC_PREFER"
cdc_ioctl_cmd_strings[206] = "WLC_GET_ASSOC_PREFER"
cdc_ioctl_cmd_strings[207] = "WLC_SET_ROAM_PREFER"
cdc_ioctl_cmd_strings[208] = "WLC_GET_ROAM_PREFER"
cdc_ioctl_cmd_strings[209] = "WLC_SET_LED"
cdc_ioctl_cmd_strings[210] = "WLC_GET_LED"
cdc_ioctl_cmd_strings[211] = "WLC_GET_INTERFERENCE_MODE"
cdc_ioctl_cmd_strings[212] = "WLC_SET_INTERFERENCE_MODE"
cdc_ioctl_cmd_strings[213] = "WLC_GET_CHANNEL_QA"
cdc_ioctl_cmd_strings[214] = "WLC_START_CHANNEL_QA"
cdc_ioctl_cmd_strings[215] = "WLC_GET_CHANNEL_SEL"
cdc_ioctl_cmd_strings[216] = "WLC_START_CHANNEL_SEL"
cdc_ioctl_cmd_strings[217] = "WLC_GET_VALID_CHANNELS"
cdc_ioctl_cmd_strings[218] = "WLC_GET_FAKEFRAG"
cdc_ioctl_cmd_strings[219] = "WLC_SET_FAKEFRAG"
cdc_ioctl_cmd_strings[220] = "WLC_GET_PWROUT_PERCENTAGE"
cdc_ioctl_cmd_strings[221] = "WLC_SET_PWROUT_PERCENTAGE"
cdc_ioctl_cmd_strings[222] = "WLC_SET_BAD_FRAME_PREEMPT"
cdc_ioctl_cmd_strings[223] = "WLC_GET_BAD_FRAME_PREEMPT"
cdc_ioctl_cmd_strings[224] = "WLC_SET_LEAP_LIST"
cdc_ioctl_cmd_strings[225] = "WLC_GET_LEAP_LIST"
cdc_ioctl_cmd_strings[226] = "WLC_GET_CWMIN"
cdc_ioctl_cmd_strings[227] = "WLC_SET_CWMIN"
cdc_ioctl_cmd_strings[228] = "WLC_GET_CWMAX"
cdc_ioctl_cmd_strings[229] = "WLC_SET_CWMAX"
cdc_ioctl_cmd_strings[230] = "WLC_GET_WET"
cdc_ioctl_cmd_strings[231] = "WLC_SET_WET"
cdc_ioctl_cmd_strings[232] = "WLC_GET_PUB"
cdc_ioctl_cmd_strings[233] = "WLC_SET_GLACIAL_TIMER"
cdc_ioctl_cmd_strings[234] = "WLC_GET_GLACIAL_TIMER"
cdc_ioctl_cmd_strings[235] = "WLC_GET_KEY_PRIMARY"
cdc_ioctl_cmd_strings[236] = "WLC_SET_KEY_PRIMARY"
cdc_ioctl_cmd_strings[237] = "WLC_DUMP_RADIOREGS"
cdc_ioctl_cmd_strings[238] = "WLC_GET_ACI_ARGS"
cdc_ioctl_cmd_strings[239] = "WLC_SET_ACI_ARGS"
cdc_ioctl_cmd_strings[240] = "WLC_UNSET_CALLBACK"
cdc_ioctl_cmd_strings[241] = "WLC_SET_CALLBACK"
cdc_ioctl_cmd_strings[242] = "WLC_GET_RADAR"
cdc_ioctl_cmd_strings[243] = "WLC_SET_RADAR"
cdc_ioctl_cmd_strings[244] = "WLC_SET_SPECT_MANAGMENT"
cdc_ioctl_cmd_strings[245] = "WLC_GET_SPECT_MANAGMENT"
cdc_ioctl_cmd_strings[246] = "WLC_WDS_GET_REMOTE_HWADDR"
cdc_ioctl_cmd_strings[247] = "WLC_WDS_GET_WPA_SUP"
cdc_ioctl_cmd_strings[248] = "WLC_SET_CS_SCAN_TIMER"
cdc_ioctl_cmd_strings[249] = "WLC_GET_CS_SCAN_TIMER"
cdc_ioctl_cmd_strings[250] = "WLC_MEASURE_REQUEST"
cdc_ioctl_cmd_strings[251] = "WLC_INIT"
cdc_ioctl_cmd_strings[252] = "WLC_SEND_QUIET"
cdc_ioctl_cmd_strings[253] = "WLC_KEEPALIVE"
cdc_ioctl_cmd_strings[254] = "WLC_SEND_PWR_CONSTRAINT"
cdc_ioctl_cmd_strings[255] = "WLC_UPGRADE_STATUS"
cdc_ioctl_cmd_strings[256] = "WLC_CURRENT_PWR"
cdc_ioctl_cmd_strings[257] = "WLC_GET_SCAN_PASSIVE_TIME"
cdc_ioctl_cmd_strings[258] = "WLC_SET_SCAN_PASSIVE_TIME"
cdc_ioctl_cmd_strings[259] = "WLC_LEGACY_LINK_BEHAVIOR"
cdc_ioctl_cmd_strings[260] = "WLC_GET_CHANNELS_IN_COUNTRY"
cdc_ioctl_cmd_strings[261] = "WLC_GET_COUNTRY_LIST"
cdc_ioctl_cmd_strings[262] = "WLC_GET_VAR"
cdc_ioctl_cmd_strings[263] = "WLC_SET_VAR"
cdc_ioctl_cmd_strings[264] = "WLC_NVRAM_GET"
cdc_ioctl_cmd_strings[265] = "WLC_NVRAM_SET"
cdc_ioctl_cmd_strings[266] = "WLC_NVRAM_DUMP"
cdc_ioctl_cmd_strings[267] = "WLC_REBOOT"
cdc_ioctl_cmd_strings[268] = "WLC_SET_WSEC_PMK"
cdc_ioctl_cmd_strings[269] = "WLC_GET_AUTH_MODE"
cdc_ioctl_cmd_strings[270] = "WLC_SET_AUTH_MODE"
cdc_ioctl_cmd_strings[271] = "WLC_GET_WAKEENTRY"
cdc_ioctl_cmd_strings[272] = "WLC_SET_WAKEENTRY"
cdc_ioctl_cmd_strings[273] = "WLC_NDCONFIG_ITEM"
cdc_ioctl_cmd_strings[274] = "WLC_NVOTPW"
cdc_ioctl_cmd_strings[275] = "WLC_OTPW"
cdc_ioctl_cmd_strings[276] = "WLC_IOV_BLOCK_GET"
cdc_ioctl_cmd_strings[277] = "WLC_IOV_MODULES_GET"
cdc_ioctl_cmd_strings[278] = "WLC_SOFT_RESET"
cdc_ioctl_cmd_strings[279] = "WLC_GET_ALLOW_MODE"
cdc_ioctl_cmd_strings[280] = "WLC_SET_ALLOW_MODE"
cdc_ioctl_cmd_strings[281] = "WLC_GET_DESIRED_BSSID"
cdc_ioctl_cmd_strings[282] = "WLC_SET_DESIRED_BSSID"
cdc_ioctl_cmd_strings[284] = "WLC_GET_NBANDS"
cdc_ioctl_cmd_strings[285] = "WLC_GET_BANDSTATES"
cdc_ioctl_cmd_strings[286] = "WLC_GET_WLC_BSS_INFO"
cdc_ioctl_cmd_strings[287] = "WLC_GET_ASSOC_INFO"
cdc_ioctl_cmd_strings[288] = "WLC_GET_OID_PHY"
cdc_ioctl_cmd_strings[289] = "WLC_SET_OID_PHY"
cdc_ioctl_cmd_strings[290] = "WLC_SET_ASSOC_TIME"
cdc_ioctl_cmd_strings[291] = "WLC_GET_DESIRED_SSID"
cdc_ioctl_cmd_strings[292] = "WLC_GET_CHANSPEC"
cdc_ioctl_cmd_strings[293] = "WLC_GET_ASSOC_STATE"
cdc_ioctl_cmd_strings[294] = "WLC_SET_PHY_STATE"
cdc_ioctl_cmd_strings[295] = "WLC_GET_SCAN_PENDING"
cdc_ioctl_cmd_strings[296] = "WLC_GET_SCANREQ_PENDING"
cdc_ioctl_cmd_strings[297] = "WLC_GET_PREV_ROAM_REASON"
cdc_ioctl_cmd_strings[298] = "WLC_SET_PREV_ROAM_REASON"
cdc_ioctl_cmd_strings[299] = "WLC_GET_BANDSTATES_PI"
cdc_ioctl_cmd_strings[300] = "WLC_GET_PHY_STATE"
cdc_ioctl_cmd_strings[301] = "WLC_GET_BSS_WPA_RSN"
cdc_ioctl_cmd_strings[302] = "WLC_GET_BSS_WPA2_RSN"
cdc_ioctl_cmd_strings[303] = "WLC_GET_BSS_BCN_TS"
cdc_ioctl_cmd_strings[304] = "WLC_GET_INT_DISASSOC"
cdc_ioctl_cmd_strings[305] = "WLC_SET_NUM_PEERS"
cdc_ioctl_cmd_strings[306] = "WLC_GET_NUM_BSS"
cdc_ioctl_cmd_strings[307] = "WLC_PHY_SAMPLE_COLLECT"
cdc_ioctl_cmd_strings[308] = "WLC_UM_PRIV"
cdc_ioctl_cmd_strings[309] = "WLC_GET_CMD"
cdc_ioctl_cmd_strings[310] = "WLC_LAST"
cdc_ioctl_cmd_strings[311] = "WLC_SET_INTERFERENCE_OVERRIDE_MODE"
cdc_ioctl_cmd_strings[312] = "WLC_GET_INTERFERENCE_OVERRIDE_MODE"
cdc_ioctl_cmd_strings[313] = "WLC_GET_WAI_RESTRICT"
cdc_ioctl_cmd_strings[314] = "WLC_SET_WAI_RESTRICT"
cdc_ioctl_cmd_strings[315] = "WLC_SET_WAI_REKEY"
cdc_ioctl_cmd_strings[316] = "WLC_SET_NAT_CONFIG"
cdc_ioctl_cmd_strings[317] = "WLC_GET_NAT_STATE"
cdc_ioctl_cmd_strings[318] = "WLC_LAST"

f.data = ProtoField.bytes("bcm_cdc_ioctl.data", "data")

f.bcm_cdc_ioctl_cmd = ProtoField.uint32("bcm_cdc_ioctl.cmd", "cmd", base.DEC, cdc_ioctl_cmd_strings)
f.bcm_cdc_ioctl_len = ProtoField.uint32("bcm_cdc_ioctl.len", "len", base.DEC)
f.bcm_cdc_ioctl_flags = ProtoField.uint32("bcm_cdc_ioctl.flags", "flags", base.HEX)
f.bcm_cdc_ioctl_status = ProtoField.uint32("bcm_cdc_ioctl.status", "status", base.DEC)


f.bcm_var_name = ProtoField.stringz("bcm_var_name", "var_name")



