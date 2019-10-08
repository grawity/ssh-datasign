
Sign with OpenSSH:

echo -n asdf | ./ssh-keygen -Y sign -n 'yay' -f ~/.ssh/id_ed25519 | tee /tmp/goodsig

Verify with OpenSSH:

echo -n asdf | ./ssh-keygen -Y verify -v -s foo.sig -n 'yay' -f <(echo "foo $(<~/.ssh/id_ed25519.pub)") -I 'foo'
