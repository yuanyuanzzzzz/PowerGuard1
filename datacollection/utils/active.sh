#!/bin/bash

echo ">>> Setting phone to ACTIVE mode..."

# 1. Force the screen to stay on while plugged in
adb shell svc power stayon true

# 2. Wake up the screen (KEYCODE_WAKEUP)
adb shell input keyevent 224

# 3. Swipe up to unlock (Pixel 3a resolution coordinates)
# From (540, 1500) to (540, 500)
adb shell input swipe 540 1500 540 500 100

echo "Success: Phone is ON and set to Stay Awake."