#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>
#include <pwd.h>
#include <stdbool.h>
#include <errno.h>

#define BRIGHTBLUE "\x1b[34;1m"
#define DEFAULT    "\x1b[0m"

#define MAX_INPUT_SIZE 1024
#define MAX_PATH_SIZE 1024
#define MAX_INPUT_LEN 4096
#define MAX_NUM_TOKENS 2048

volatile sig_atomic_t interrupted = 0;
void run_shell();

void sigint_handler(int sig) {
		interrupted = 1;
}

char *expand_tilde(const char *path) {
    if (path[0] == '~') {
        char *new_path = malloc(MAX_PATH_SIZE);
        uid_t uid = getuid();
        struct passwd *pw = getpwuid(uid);

        if (pw) {
            strcpy(new_path, pw->pw_dir);
            strcat(new_path, path + 1);
            return new_path;
        } else {
            fprintf(stderr, "Error: Cannot get passwd entry. %s.\n", strerror(errno));
            exit(EXIT_FAILURE);
        }
    }
    return strdup(path);
}

void change_directory(char *path) {
    char *expanded_path = expand_tilde(path);
    if (chdir(expanded_path) != 0) {
        fprintf(stderr, "Error: Cannot change directory to '%s'. %s.\n", expanded_path, strerror(errno));
    }

    free(expanded_path);
}

char *get_next_token(char *input, int *pos) {
    int start = *pos;
    char *token;
    int token_len = 0;
    int in_quotes = 0;
    while (input[*pos] != '\0') {
        if (input[*pos] == '\"') {
	    if(in_quotes == 0) {
		    in_quotes = 1;
	    } else {
		    in_quotes = 0;
	    }
            (*pos)++;
            continue;
	}
	if(!in_quotes && input[*pos] == ' ') {
		(*pos)++;
		break;
	}
        token_len++;
        (*pos)++;
    }

    if (token_len > 0) {
        token = malloc(token_len + 1);
        if (token == NULL) {
            fprintf(stderr, "Error: malloc() failed. %s.\n", strerror(errno));
            exit(EXIT_FAILURE);
        }
        int token_pos = 0;
        for (int i = start; i < *pos; i++) {
            if (input[i] != '\"') {
                token[token_pos++] = input[i];
            }
        }
        token[token_len] = '\0';
    } else {
        token = NULL;
    }

    return token;
}

bool check_quotes_balance(const char *input) {
    int quotes = 0;
    for (int i = 0; input[i] != '\0'; i++) {
        if (input[i] == '\"') {
            quotes++;
        }
    }
    return quotes % 2 == 0;
}

void run_shell() {
    char input[MAX_INPUT_LEN];
    char cwd[MAX_PATH_SIZE];

    while (1) {
	if (signal(SIGINT, sigint_handler) == SIG_ERR) {
        	fprintf(stderr, "Error: Cannot register signal handler. %s.\n", strerror(errno));
        	exit(EXIT_FAILURE);
    	}
        if (getcwd(cwd, sizeof(cwd)) != NULL) {
            	printf("%s[%s]%s$ ", BRIGHTBLUE, cwd, DEFAULT);
        } else {
            	fprintf(stderr, "Error: Cannot get current working directory. %s.\n", strerror(errno));
	    	exit(EXIT_FAILURE);
	}
	if (fgets(input, MAX_INPUT_SIZE, stdin) == NULL) {
        	if(errno == EINTR) {
			printf("\n");
			interrupted = 0;
			continue;
		}
		fprintf(stderr, "Error: Failed to read from stdin. %s.\n", strerror(errno));
        	exit(EXIT_SUCCESS);
    	}

    	input[strcspn(input, "\n")] = 0;
    	if (!check_quotes_balance(input)) {
        	printf("Error: Unbalanced quotes, there must be an even number of quotes.\n");
        	printf("Exiting...\n");
        	exit(EXIT_FAILURE);
    	}

    	int pos = 0;
    	char *command = get_next_token(input, &pos);
    	if (command == NULL) {
        	continue;
    	} else if (strcmp(command, "exit") == 0) {
        	free(command);
        	exit(EXIT_SUCCESS);
    	} else if (strcmp(command, "cd") == 0) {
        	char *path = get_next_token(input, &pos);
        	if (path == NULL) {
        	    	change_directory("~");
        	} else {
            		change_directory(path);
            		free(path);
        	}
    	} else {
        	pid_t pid = fork();
        	if (pid < 0) {
            		fprintf(stderr, "Error: fork() failed. %s.\n", strerror(errno));
			free(command);
			exit(EXIT_FAILURE);
        	} else if (pid == 0) {
        	    	if (signal(SIGINT, SIG_DFL) == SIG_ERR) {
        			fprintf(stderr, "Error: Cannot reset signal handler. %s.\n", strerror(errno));
        			free(command);
				exit(EXIT_FAILURE);
    			}	
			char *args[MAX_INPUT_SIZE] = {command};
            		int i = 1;
            		char *arg;
            		int num_tokens = 0;
            		while ((arg = get_next_token(input, &pos)) != NULL) {
                		args[i++] = arg;
                		num_tokens++;
            		}
            		if (num_tokens > MAX_NUM_TOKENS) {
                		printf("Error: Too many tokens in the input. Maximum allowed tokens: %d\n", MAX_NUM_TOKENS);
                		free(command);
				exit(EXIT_FAILURE);
            		}
            		args[i] = NULL;
            		if (execvp(command, args) == -1) {
                		fprintf(stderr, "Error: exec() failed. %s.\n", strerror(errno));
                		free(command);
				exit(EXIT_FAILURE);
            		}
        	} else {
            		int status;
            		if (waitpid(pid, &status, 0) < 0) {
                		fprintf(stderr, "Error: wait() failed. %s.\n", strerror(errno));
            		}
			if(interrupted) {
				printf("\n");
				interrupted = 0;
			}
        	}
    	}
    	free(command);
}}

int main() {
    run_shell();
    return 0;
}
