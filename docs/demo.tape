Output docs/demo.gif
Set FontSize 15
Set Width 1300
Set Height 560
Set Padding 16
Set TypingSpeed 35ms
Set Shell "bash"
Hide
Type "export PATH=$PWD/target/release:$PATH; clear" Enter
Show
Type "honest-server check zec.rocks:443" Enter
Wait+Screen@60s /NU7 /
Sleep 3s
Type "honest-server check zec.rocks:443 --test-drop-note" Enter
Wait+Screen@60s /MISMATCH/
Sleep 5s
