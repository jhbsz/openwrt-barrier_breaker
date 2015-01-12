#!/bin/sh
append DRIVERS "mt7610"

. /lib/wifi/ralink_common.sh

prepare_mt7610() {
	prepare_ralink_wifi mt7610
}

scan_mt7610() {
	scan_ralink_wifi mt7610 mt7610
}

disable_mt7610() {
	disable_ralink_wifi mt7610
}

enable_mt7610() {
	enable_ralink_wifi mt7610 mt7610
}

detect_mt7610() {
	detect_ralink_wifi mt7610 mt7610
}


