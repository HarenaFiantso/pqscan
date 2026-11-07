# SPDX-License-Identifier: Apache-2.0
#
# Records the README demo. From the repository root, after a release build:
#
#     vhs assets/demo.tape

Output assets/demo.gif

Set Shell "bash"
Set FontSize 20
Set Width 1000
Set Height 520
Set Padding 24
Set Framerate 15
Set Theme "Catppuccin Mocha"
Set TypingSpeed 45ms

Hide
Type "export PATH=$PWD/build/release:$PATH && clear"
Enter
Sleep 300ms
Show

Sleep 500ms
Type "pqscan --version"
Sleep 300ms
Enter
Sleep 1500ms

Type "pqscan tests/fixtures/scan/findings"
Sleep 300ms
Enter
Sleep 3s

Type "echo $?"
Sleep 300ms
Enter
Sleep 1500ms

Type "pqscan --ignore '*.hpp' tests/fixtures/scan/findings"
Sleep 300ms
Enter
Sleep 3s

Type "pqscan tests/fixtures/scan/clean; echo $?"
Sleep 300ms
Enter
Sleep 3s
