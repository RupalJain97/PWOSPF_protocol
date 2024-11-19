# PWOSPF_protocol

## Instructions for running the code:

Open 4 terminals and ssh to lectura on all 4 of them and then make sure you're inside the correct project directory/folder named 
'topXXX', where 'XXX' is topology ID.

On terminal 1, run the first router (vhost1) with rtable.net as follows:
./sr -t XXX -v vhost1 -r rtable.net

On terminal 2, run the second router (vhost2) with rtable.empty as follows:
./sr -t XXX -v vhost2 -r rtable.empty

On terminal 3, run the third router (vhost3) with rtable.empty as follows:
./sr -t XXX -v vhost3 -r rtable.empty

On terminal 4, run any ping, wget or link up/down command you want to run.
E.g. in terminal 4 you can do: wget http://ip_of_server2:16280/64MB.bin
or ping ip_of_server1 etc.