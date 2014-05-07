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
local bcm = Proto("bcmwlan", "BCM WLAN dissector")
local f = bcm.fields
local event_type_strings = {}

function bcm.init()
	local udp_table = DissectorTable.get("ethertype")
	local pattern = 0xBC01
	udp_table:add(pattern, bcm)
end


function bcm.dissector(inbuffer, pinfo, tree)
	local n = 0
	local buffer = inbuffer
	pinfo.cols.protocol = "bcm-event"
	pinfo.cols.info = ""

	local subtree = tree:add(bcm, buffer(), "BCM Event protocol data")

	subtree:add_le(f.event_version, buffer(n, 2)); n = n + 2
	subtree:add_le(f.event_flags, buffer(n, 2)); n = n + 2
	local event_type = buffer(n, 4)
	subtree:add_le(f.event_event_type, event_type); n = n + 4
	subtree:add_le(f.event_status, buffer(n, 4)); n = n + 4
	subtree:add_le(f.event_reason, buffer(n, 4)); n = n + 4
	subtree:add_le(f.event_auth_type, buffer(n, 4)); n = n + 4
	subtree:add_le(f.event_datalen, buffer(n, 4)); n = n + 4
	subtree:add_le(f.event_addr, buffer(n, 6)); n = n + 6
	subtree:add_le(f.event_ifname, buffer(n, 16)); n = n + 16
	subtree:add_le(f.event_ifidx, buffer(n, 1)); n = n + 1
	subtree:add_le(f.event_bsscfgidx, buffer(n, 1)); n = n + 1

	local event_type_int = event_type:le_uint()
	if event_type_strings[event_type_int] ~= nil then
		pinfo.cols.info:append(event_type_strings[event_type_int]:lower())
	else
		pinfo.cols.info:append("unknown event")
	end

--typedef struct {
--	uint16                     version;              /*     0     2 */
--	uint16                     flags;                /*     2     2 */
--	uint32                     event_type;           /*     4     4 */
--	uint32                     status;               /*     8     4 */
--	uint32                     reason;               /*    12     4 */
--	uint32                     auth_type;            /*    16     4 */
--	uint32                     datalen;              /*    20     4 */
--	struct ether_addr          addr;                 /*    24     6 */
--	char                       ifname[16];           /*    30    16 */
--	uint8                      ifidx;                /*    46     1 */
--	uint8                      bsscfgidx;            /*    47     1 */
--
--	/* size: 48, cachelines: 1, members: 11 */
--	/* last cacheline: 48 bytes */
--} wl_event_msg_t;
end

event_type_strings[0] = "WLC_E_SET_SSID"
event_type_strings[1] = "WLC_E_JOIN"
event_type_strings[2] = "WLC_E_START"
event_type_strings[3] = "WLC_E_AUTH"
event_type_strings[4] = "WLC_E_AUTH_IND"
event_type_strings[5] = "WLC_E_DEAUTH"
event_type_strings[6] = "WLC_E_DEAUTH_IND"
event_type_strings[7] = "WLC_E_ASSOC"
event_type_strings[8] = "WLC_E_ASSOC_IND"
event_type_strings[9] = "WLC_E_REASSOC"
event_type_strings[10] = "WLC_E_REASSOC_IND"
event_type_strings[11] = "WLC_E_DISASSOC"
event_type_strings[12] = "WLC_E_DISASSOC_IND"
event_type_strings[13] = "WLC_E_QUIET_START"
event_type_strings[14] = "WLC_E_QUIET_END"
event_type_strings[15] = "WLC_E_BEACON_RX"
event_type_strings[16] = "WLC_E_LINK"
event_type_strings[17] = "WLC_E_MIC_ERROR"
event_type_strings[18] = "WLC_E_NDIS_LINK"
event_type_strings[19] = "WLC_E_ROAM"
event_type_strings[20] = "WLC_E_TXFAIL"
event_type_strings[21] = "WLC_E_PMKID_CACHE"
event_type_strings[22] = "WLC_E_RETROGRADE_TSF"
event_type_strings[23] = "WLC_E_PRUNE"
event_type_strings[24] = "WLC_E_AUTOAUTH"
event_type_strings[25] = "WLC_E_EAPOL_MSG"
event_type_strings[26] = "WLC_E_SCAN_COMPLETE"
event_type_strings[27] = "WLC_E_ADDTS_IND"
event_type_strings[28] = "WLC_E_DELTS_IND"
event_type_strings[29] = "WLC_E_BCNSENT_IND"
event_type_strings[30] = "WLC_E_BCNRX_MSG"
event_type_strings[31] = "WLC_E_BCNLOST_MSG"
event_type_strings[32] = "WLC_E_ROAM_PREP"
event_type_strings[33] = "WLC_E_PFN_NET_FOUND"
event_type_strings[34] = "WLC_E_PFN_NET_LOST"
event_type_strings[35] = "WLC_E_RESET_COMPLETE"
event_type_strings[36] = "WLC_E_JOIN_START"
event_type_strings[37] = "WLC_E_ROAM_START"
event_type_strings[38] = "WLC_E_ASSOC_START"
event_type_strings[39] = "WLC_E_IBSS_ASSOC"
event_type_strings[40] = "WLC_E_RADIO"
event_type_strings[41] = "WLC_E_PSM_WATCHDOG"
event_type_strings[44] = "WLC_E_PROBREQ_MSG"
event_type_strings[45] = "WLC_E_SCAN_CONFIRM_IND"
event_type_strings[46] = "WLC_E_PSK_SUP"
event_type_strings[47] = "WLC_E_COUNTRY_CODE_CHANGED"
event_type_strings[49] = "WLC_E_ICV_ERROR"
event_type_strings[50] = "WLC_E_UNICAST_DECODE_ERROR"
event_type_strings[51] = "WLC_E_MULTICAST_DECODE_ERROR"
event_type_strings[52] = "WLC_E_TRACE"
event_type_strings[54] = "WLC_E_IF"
event_type_strings[55] = "WLC_E_P2P_DISC_LISTEN_COMPLETE"
event_type_strings[56] = "WLC_E_RSSI"
event_type_strings[57] = "WLC_E_PFN_BEST_BATCHING"
event_type_strings[57] = "WLC_E_PFN_SCAN_COMPLETE"
event_type_strings[57] = "WLC_E_PFN_BEST_BATCHING"
event_type_strings[58] = "WLC_E_EXTLOG_MSG"
event_type_strings[59] = "WLC_E_ACTION_FRAME"
event_type_strings[60] = "WLC_E_ACTION_FRAME_COMPLETE"
event_type_strings[61] = "WLC_E_PRE_ASSOC_IND"
event_type_strings[62] = "WLC_E_PRE_REASSOC_IND"
event_type_strings[63] = "WLC_E_CHANNEL_ADOPTED"
event_type_strings[64] = "WLC_E_AP_STARTED"
event_type_strings[65] = "WLC_E_DFS_AP_STOP"
event_type_strings[66] = "WLC_E_DFS_AP_RESUME"
event_type_strings[67] = "WLC_E_WAI_STA_EVENT"
event_type_strings[68] = "WLC_E_WAI_MSG"
event_type_strings[69] = "WLC_E_ESCAN_RESULT"
event_type_strings[70] = "WLC_E_ACTION_FRAME_OFF_CHAN_COMPLETE"
event_type_strings[71] = "WLC_E_PROBRESP_MSG"
event_type_strings[72] = "WLC_E_P2P_PROBREQ_MSG"
event_type_strings[73] = "WLC_E_DCS_REQUEST"
event_type_strings[74] = "WLC_E_FIFO_CREDIT_MAP"
event_type_strings[75] = "WLC_E_ACTION_FRAME_RX"
event_type_strings[76] = "WLC_E_WAKE_EVENT"
event_type_strings[77] = "WLC_E_RM_COMPLETE"
event_type_strings[78] = "WLC_E_HTSFSYNC"
event_type_strings[79] = "WLC_E_OVERLAY_REQ"
event_type_strings[80] = "WLC_E_CSA_COMPLETE_IND"
event_type_strings[81] = "WLC_E_EXCESS_PM_WAKE_EVENT"
event_type_strings[82] = "WLC_E_PFN_SCAN_NONE"
event_type_strings[82] = "WLC_E_PFN_BSSID_NET_FOUND"
event_type_strings[83] = "WLC_E_PFN_SCAN_ALLGONE"
event_type_strings[83] = "WLC_E_PFN_BSSID_NET_LOST"
event_type_strings[84] = "WLC_E_GTK_PLUMBED"
event_type_strings[85] = "WLC_E_ASSOC_IND_NDIS"
event_type_strings[86] = "WLC_E_REASSOC_IND_NDIS"
event_type_strings[87] = "WLC_E_ASSOC_REQ_IE"
event_type_strings[88] = "WLC_E_ASSOC_RESP_IE"
event_type_strings[89] = "WLC_E_ASSOC_RECREATED"
event_type_strings[90] = "WLC_E_ACTION_FRAME_RX_NDIS"
event_type_strings[91] = "WLC_E_AUTH_REQ"
event_type_strings[92] = "WLC_E_TDLS_PEER_EVENT"
event_type_strings[93] = "WLC_E_SPEEDY_RECREATE_FAIL"


f.event_version = ProtoField.uint16("bcm_event.version", "version", base.DEC)
f.event_flags = ProtoField.uint16("bcm_event.flags", "flags")
f.event_event_type = ProtoField.uint32("bcm_event.event_type", "event_type", base.DEC, event_type_strings)
f.event_status = ProtoField.uint32("bcm_event.status", "status", base.DEC)
f.event_reason = ProtoField.uint32("bcm_event.reason", "reason", base.DEC)
f.event_auth_type = ProtoField.uint32("bcm_event.auth_type", "auth_type", base.DEC)
f.event_datalen = ProtoField.uint32("bcm_event.datalen", "datalen", base.DEC)
f.event_addr = ProtoField.ether("bcm_event.addr", "addr")
f.event_ifname = ProtoField.bytes("bcm_event.ifname", "ifname")
f.event_ifidx = ProtoField.uint8("bcm_event.ifidx", "ifidx", base.DEC)
f.event_bsscfgidx = ProtoField.uint8("bcm_event.bsscfgidx", "bsscfgidx", base.DEC)

--typedef struct {
--	uint16                     version;              /*     0     2 */
--	uint16                     flags;                /*     2     2 */
--	uint32                     event_type;           /*     4     4 */
--	uint32                     status;               /*     8     4 */
--	uint32                     reason;               /*    12     4 */
--	uint32                     auth_type;            /*    16     4 */
--	uint32                     datalen;              /*    20     4 */
--	struct ether_addr          addr;                 /*    24     6 */
--	char                       ifname[16];           /*    30    16 */
--	uint8                      ifidx;                /*    46     1 */
--	uint8                      bsscfgidx;            /*    47     1 */
--
--	/* size: 48, cachelines: 1, members: 11 */
--	/* last cacheline: 48 bytes */
--} wl_event_msg_t;

