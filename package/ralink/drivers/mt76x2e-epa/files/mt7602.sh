#!/bin/sh
append DRIVERS "mt7602"

. /lib/wifi/ralink_common.sh

prepare_mt7602() {
	prepare_ralink_wifi mt7602
}

scan_mt7602() {
	scan_ralink_wifi mt7602 mt76x2e
}

disable_mt7602() {
	disable_ralink_wifi mt7602
}

enable_mt7602() {
	enable_ralink_wifi mt7602 mt76x2e
}

detect_mt7602() {
	detect_ralink_wifi mt7602 mt76x2e
}


