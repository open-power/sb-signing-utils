all: create-software-container create-container

create-container: create-container.c
	$(CC) -g -Wall -Wextra -I. $^ -o $@ -lssl -lcrypto -std=gnu99

create-software-container: create-software-container.c
	$(CC) -g -Wall -Wextra -I. $^ -o $@ -lssl -lcrypto -std=gnu99

clean:
	$(RM) create-software-container create-container

