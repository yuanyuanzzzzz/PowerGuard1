#!/bin/bash

echo ">>> Setting phone to IDLE mode..."

# 1. Allow the screen to turn off (disable stayon)
adb shell svc power stayon false

# 2. Put device to sleep (KEYCODE_SLEEP)
adb shell input keyevent 223

# 3. Wait a moment for system to react
sleep 1

# 4. Verify the screen status
# We grep for mScreenOnFully. If false, the screen is black.
echo "Checking screen status..."
status=$(adb shell dumpsys window policy | grep "mScreenOnFully")

echo "Current Status: $status"
echo "Done. (If mScreenOnFully=false, the screen is OFF)."