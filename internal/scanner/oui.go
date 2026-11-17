package scanner

import "strings"

// vendorFor returns a human-friendly vendor name for a MAC's OUI (first 24 bits),
// or "" if we don't know it. The table below covers the most common consumer
// device vendors — enough to usefully label unknown MACs in presence alerts.
// Expand it in future with ieee.org's oui.csv if needed; for now it stays tiny
// to keep the binary small.
func vendorFor(mac string) string {
	// MAC comes in lowercase "aa:bb:cc:dd:ee:ff"; take the first 8 chars "aa:bb:cc".
	if len(mac) < 8 {
		return ""
	}
	prefix := strings.ToUpper(mac[:8])
	// Locally-administered bit = 1 means randomized (iOS/Android privacy MAC).
	// First octet with bit 2 set (0x02): "02, 06, 0a, 0e, …, fa, fe".
	if len(prefix) >= 2 {
		switch prefix[1] {
		case '2', '6', 'A', 'E':
			return "Randomized"
		}
	}
	return ouiTable[prefix]
}

var ouiTable = map[string]string{
	// Apple
	"00:03:93": "Apple", "00:05:02": "Apple", "00:0A:27": "Apple", "00:0A:95": "Apple",
	"00:0D:93": "Apple", "00:10:FA": "Apple", "00:11:24": "Apple", "00:14:51": "Apple",
	"00:16:CB": "Apple", "00:17:F2": "Apple", "00:19:E3": "Apple", "00:1B:63": "Apple",
	"00:1C:B3": "Apple", "00:1D:4F": "Apple", "00:1E:52": "Apple", "00:1E:C2": "Apple",
	"00:1F:5B": "Apple", "00:1F:F3": "Apple", "00:21:E9": "Apple", "00:22:41": "Apple",
	"00:23:12": "Apple", "00:23:32": "Apple", "00:23:6C": "Apple", "00:23:DF": "Apple",
	"00:24:36": "Apple", "00:25:00": "Apple", "00:25:4B": "Apple", "00:25:BC": "Apple",
	"00:26:08": "Apple", "00:26:4A": "Apple", "00:26:B0": "Apple", "00:26:BB": "Apple",
	"04:0C:CE": "Apple", "14:10:9F": "Apple", "20:A2:E4": "Apple", "28:CF:DA": "Apple",
	"34:C0:59": "Apple", "3C:07:54": "Apple", "48:60:BC": "Apple", "58:55:CA": "Apple",
	"68:AB:BC": "Apple", "88:1F:A1": "Apple", "A4:5E:60": "Apple", "A8:60:B6": "Apple",
	"B4:F0:AB": "Apple", "C8:BC:C8": "Apple", "D4:DC:CD": "Apple", "DC:9B:9C": "Apple",
	"E0:AC:CB": "Apple", "F0:18:98": "Apple",

	// Samsung
	"00:07:AB": "Samsung", "00:12:FB": "Samsung", "00:15:99": "Samsung", "00:17:C9": "Samsung",
	"00:1A:8A": "Samsung", "00:1D:F6": "Samsung", "00:21:19": "Samsung", "00:23:39": "Samsung",
	"00:26:37": "Samsung", "08:08:C2": "Samsung", "14:49:E0": "Samsung", "20:D3:90": "Samsung",
	"28:BA:B5": "Samsung", "34:23:BA": "Samsung", "3C:A1:0D": "Samsung", "50:CC:F8": "Samsung",
	"5C:0A:5B": "Samsung", "78:F8:82": "Samsung", "88:32:9B": "Samsung", "9C:02:98": "Samsung",
	"A0:0B:BA": "Samsung", "C4:42:02": "Samsung", "E8:50:8B": "Samsung", "F4:09:D8": "Samsung",

	// Xiaomi / Redmi
	"0C:1D:AF": "Xiaomi", "14:F6:5A": "Xiaomi", "28:6C:07": "Xiaomi", "34:80:B3": "Xiaomi",
	"38:A4:ED": "Xiaomi", "50:8F:4C": "Xiaomi", "58:44:98": "Xiaomi", "64:09:80": "Xiaomi",
	"68:DF:DD": "Xiaomi", "74:51:BA": "Xiaomi", "78:11:DC": "Xiaomi", "8C:BE:BE": "Xiaomi",
	"98:FA:E3": "Xiaomi", "A0:86:C6": "Xiaomi", "AC:C1:EE": "Xiaomi", "C4:0B:CB": "Xiaomi",
	"F0:B4:29": "Xiaomi", "F4:F5:DB": "Xiaomi", "F8:A4:5F": "Xiaomi",

	// OnePlus
	"64:A2:F9": "OnePlus", "94:65:2D": "OnePlus", "C0:EE:FB": "OnePlus",

	// Google / Nest
	"00:1A:11": "Google", "F4:F5:E8": "Google", "F4:F5:D8": "Google", "F4:F5:D9": "Google",
	"AA:66:51": "Google", "20:DF:B9": "Nest", "64:16:66": "Nest",

	// Amazon (Echo, Fire, Ring)
	"00:71:47": "Amazon", "1C:FE:2B": "Amazon", "34:D2:70": "Amazon", "40:B4:CD": "Amazon",
	"44:00:10": "Amazon", "50:DC:E7": "Amazon", "68:54:FD": "Amazon", "78:E1:03": "Amazon",
	"84:D6:D0": "Amazon", "F0:D2:F1": "Amazon", "F0:F0:A4": "Amazon",

	// Intel (NUCs, laptops)
	"00:03:47": "Intel", "00:0C:F1": "Intel", "00:13:02": "Intel", "00:16:76": "Intel",
	"00:1B:21": "Intel", "00:1E:67": "Intel", "00:24:D7": "Intel", "0C:84:DC": "Intel",
	"34:F6:4B": "Intel", "48:51:B7": "Intel", "48:F1:7F": "Intel", "68:07:15": "Intel",
	"74:E5:0B": "Intel", "8C:16:45": "Intel", "9C:FC:E8": "Intel", "A0:88:69": "Intel",
	"A0:C5:89": "Intel", "AC:72:89": "Intel", "B4:B6:76": "Intel",

	// Raspberry Pi Foundation
	"28:CD:C1": "Raspberry Pi", "B8:27:EB": "Raspberry Pi", "D8:3A:DD": "Raspberry Pi",
	"DC:A6:32": "Raspberry Pi", "E4:5F:01": "Raspberry Pi",

	// TP-Link
	"00:14:78": "TP-Link", "14:EB:B6": "TP-Link", "34:60:F9": "TP-Link",
	"50:C7:BF": "TP-Link", "54:AF:97": "TP-Link", "C4:E9:84": "TP-Link",

	// Realtek chipset (common in cheap USB WiFi)
	"00:E0:4C": "Realtek", "52:54:00": "Realtek",

	// ESP32 / ESP8266 (Espressif)
	"24:0A:C4": "Espressif", "24:B2:DE": "Espressif", "30:AE:A4": "Espressif",
	"3C:71:BF": "Espressif", "40:F5:20": "Espressif", "50:02:91": "Espressif",
	"54:5A:A6": "Espressif", "84:F3:EB": "Espressif", "A0:20:A6": "Espressif",
	"AC:67:B2": "Espressif", "BC:DD:C2": "Espressif", "C4:4F:33": "Espressif",
	"C8:2B:96": "Espressif", "D8:A0:1D": "Espressif", "DC:4F:22": "Espressif",
	"EC:FA:BC": "Espressif", "F0:08:D1": "Espressif",

	// Vivo / Oppo / Realme (shared BBK group)
	"A0:47:D7": "Realme/Oppo", "DC:72:9B": "Vivo",

	// Huawei
	"00:18:82": "Huawei", "00:25:9E": "Huawei", "20:F3:A3": "Huawei",
	"44:55:C4": "Huawei", "80:B6:86": "Huawei", "E0:19:1D": "Huawei",

	// Sony
	"00:1A:80": "Sony", "54:42:49": "Sony", "F0:BF:97": "Sony",

	// LG
	"00:1E:75": "LG", "00:1F:6B": "LG", "00:22:A9": "LG",
	"3C:BD:D8": "LG", "A8:16:B2": "LG", "CC:FA:00": "LG",
}
