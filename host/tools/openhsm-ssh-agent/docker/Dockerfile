# Minimal sshd target to test OpenHSM-backed SSH login end-to-end.
# The device's Ed25519 public key (authorized_keys) is the only way in.
FROM alpine:3.20

RUN apk add --no-cache openssh-server && ssh-keygen -A \
 && adduser -D -s /bin/sh tester \
 && sed -i 's/^tester:!:/tester:*:/' /etc/shadow   # unlock account (pubkey-only, no password)

COPY authorized_keys /home/tester/.ssh/authorized_keys
RUN chown -R tester:tester /home/tester/.ssh \
 && chmod 700 /home/tester/.ssh \
 && chmod 600 /home/tester/.ssh/authorized_keys

# Key-only login.
RUN sed -i \
    -e 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' \
    -e 's/^#\?PubkeyAuthentication.*/PubkeyAuthentication yes/' \
    -e 's/^#\?PermitRootLogin.*/PermitRootLogin no/' \
    /etc/ssh/sshd_config

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
