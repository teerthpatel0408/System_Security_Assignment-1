#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>

#define MAX_USERS 10
#define MAX_PASSWORDS 10
#define MAX_PASSWORD_LENGTH 20
#define MIN_PASSWORD_LENGTH 12
#define BACKOFF_TIMES {8, 16, 32}

typedef struct {
    char username[50];
    char date_of_birth[11];
    char password_file_name[20];
} User;

User users[MAX_USERS];
int user_count = 0;

void load_users() {
    FILE *file = fopen("masterfile.txt", "r");
    if (!file) {
        perror("Failed to open masterfile.txt");
        exit(EXIT_FAILURE);
    }

    while (fscanf(file, "%s %s %s", users[user_count].username, users[user_count].date_of_birth, users[user_count].password_file_name) != EOF) {
        user_count++;
    }

    fclose(file);
}

int authenticate_user(const char *username, const char *password) {
    for (int i = 0; i < user_count; i++) {
        if (strcmp(users[i].username, username) == 0) {
            FILE *file = fopen(users[i].password_file_name, "r");
            if (!file) {
                perror("Failed to open password file");
                exit(EXIT_FAILURE);
            }

            char stored_password[MAX_PASSWORD_LENGTH + 1];
            fscanf(file, "%s", stored_password);
            fclose(file);
            if (strcmp(stored_password, password) == 0) {
                return i;
            } else {
                return -1;
            }
        }
    }
    return -1;
}

char *strcasestr(const char *haystack, const char *needle) {
    if (!*needle) return (char *)haystack;
    for (const char *p = haystack; *p; p++) {
        if (tolower((unsigned char)*p) == tolower((unsigned char)*needle)) {
            const char *h, *n;
            for (h = p, n = needle; *h && *n; h++, n++) {
                if (tolower((unsigned char)*h) != tolower((unsigned char)*n)) break;
            }
            if (!*n) return (char *)p;
        }
    }
    return NULL;
}

int validate_password(const char *username, const char *dob, const char *new_password, char *passwords[], int password_count) {
    int flag=0;
    int length = strlen(new_password);
    if (length < MIN_PASSWORD_LENGTH) {
        printf("Password does not contain a minimum of 12 characters.\n");
        flag=1;
    }

    int has_upper = 0, has_lower = 0, has_digit = 0, has_special = 0;
    for (int i = 0; i < length; i++) {
        if (isupper(new_password[i])) has_upper = 1;
        if (islower(new_password[i])) has_lower = 1;
        if (isdigit(new_password[i])) has_digit = 1;
        if (strchr(".@!#$%^&*-_", new_password[i])) has_special = 1;
    }

    if (!has_upper) {
        printf("Password does not contain at least one uppercase letter.\n");
        flag=1;
    }
    if (!has_lower) {
        printf("Password does not contain at least one lowercase letter.\n");
        flag=1;
    }
    if (!has_digit) {
        printf("Password does not contain at least one digit.\n");
        flag=1;
    }
    if (!has_special) {
        printf("Password does not contain at least one of the allowed special characters.\n");
        flag=1;
    }

    // R6: Check for more than 4 consecutive matching characters between the new and old passwords
    int max_match = 0;  // Track the maximum consecutive match

    for (int i = 0; i < password_count; i++) {
        int old_len = strlen(passwords[i]);
        int new_len = strlen(new_password);

        // Iterate over the new password
        for (int j = 0; j < new_len; j++) {
            for (int k = 0; k < old_len; k++) {
                int match_count = 0;

                // Compare characters while they match
                while (j + match_count < new_len && k + match_count < old_len &&
                       tolower(new_password[j + match_count]) == tolower(passwords[i][k + match_count])) {
                    match_count++;
                }

                // Keep track of the longest match found
                if (match_count > max_match) {
                    max_match = match_count;
                }
            }
        }
    }

    // After checking all passwords, print the maximum match if it exceeds 4
    if (max_match > 4) {
        printf("Password contains %d characters consecutively similar to one of the past 10 passwords.\n", max_match);
        flag = 1;  // Invalid password
    }


    char name[50], surname[50];
    sscanf(username, "%[^.].%s", name, surname);
    if(strcasestr(new_password, name) && strcasestr(new_password, surname)){
        printf("Password contains both name and surname portion of the username.\n");
        flag=1;
    }
    else if (strcasestr(new_password, name)) {
        printf("Password contains name portion of the username.\n");
        flag=1;
    }
    else if (strcasestr(new_password, surname)) {
        printf("Password contains surname portion of username.\n");
        flag=1;
    }

    char dob_digits[9];
    sscanf(dob, "%2s-%2s-%4s", dob_digits, dob_digits + 2, dob_digits + 4);
    dob_digits[8] = '\0';

    int max_consecutive = 0;
    int password_len = strlen(new_password);
    int dob_len = strlen(dob_digits);

    for (int i = 0; i < password_len; i++) {
        int current_consecutive = 0;

        for (int j = 0; j < dob_len; j++) {
            current_consecutive = 0;

            for (int k = 0; (i + k) < password_len && (j + k) < dob_len; k++) {
                if (new_password[i + k] == dob_digits[j + k]) {
                    current_consecutive++;
                } else {
                    break;
                }
            }

            if (current_consecutive > max_consecutive) {
                max_consecutive = current_consecutive;
            }

            if (max_consecutive > 3) {
                printf("Password contains %d digits consecutively similar to the date of birth.\n", max_consecutive);
                flag=1;
                return 0;
            }
        }
    }

    if(flag){
        return 0;
    } else {
        return 1;
    }
}

void update_password_file(const char *password_file_name, const char *new_password) {
    FILE *file = fopen(password_file_name, "r+");
    if (!file) {
        perror("Failed to open password file");
        exit(EXIT_FAILURE);
    }

    char passwords[MAX_PASSWORDS][MAX_PASSWORD_LENGTH + 1];
    int password_count = 0;
    while (fscanf(file, "%s", passwords[password_count]) != EOF && password_count < MAX_PASSWORDS) {
        password_count++;
    }

    fseek(file, 0, SEEK_SET);
    fprintf(file, "%s\n", new_password);
    for (int i = 0; i < password_count && i < MAX_PASSWORDS - 1; i++) {
        fprintf(file, "%s\n", passwords[i]);
    }

    fclose(file);
}

int main() {
    load_users();

    char username[50], password[MAX_PASSWORD_LENGTH + 1];
    int user_index = -1;

    while (user_index == -1) {
        printf("Enter username: ");
        scanf("%s", username);

        // Check if username is valid
        int valid_username = 0;
        for (int i = 0; i < user_count; i++) {
            if (strcmp(users[i].username, username) == 0) {
                valid_username = 1;
                break;
            }
        }

        if (!valid_username) {
            printf("The Username is Incorrect please try again.\n");
            continue;  // Prompt for username again
        }

        for (int attempts = 0; attempts < 3; attempts++) {
            printf("Enter password: ");
            scanf("%s", password);

            user_index = authenticate_user(username, password);
            if (user_index != -1) {
                break;
            } else {
                printf("Wrong password! Enter password again:\n");
            }
        }

        if (user_index == -1) {
            printf("Wrong password entered 3 times. Application exiting....\n");
            return 0;
        }
    }

    const int backoff_times[] = BACKOFF_TIMES;
    char new_password[MAX_PASSWORD_LENGTH + 1];
    char *passwords[MAX_PASSWORDS];
    int password_count = 0;

    FILE *file = fopen(users[user_index].password_file_name, "r");
    if (!file) {
        perror("Failed to open password file");
        exit(EXIT_FAILURE);
    }
    for (int i = 0; i < MAX_PASSWORDS; i++) {
        passwords[i] = malloc(MAX_PASSWORD_LENGTH + 1);
    }

    while (password_count < MAX_PASSWORDS && fscanf(file, "%s", passwords[password_count]) != EOF) {
        password_count++;
    }

    fclose(file);
    for (int attempts = 0; attempts < 4; attempts++) {
        printf("Enter your new password (%d attempt): ", attempts + 1);
        scanf("%s", new_password);

        if (validate_password(users[user_index].username, users[user_index].date_of_birth, new_password, passwords, password_count)) {
            update_password_file(users[user_index].password_file_name, new_password);
            printf("Password changed successfully.\n");
            return 0;
        } else {
            if (attempts < 3) {
                printf("%d attempt failed.\n", attempts + 1);
                for (int i = backoff_times[attempts]; i > 0; i--) {
                    printf("Wait for %d seconds....\n", i);
                    sleep(1);
                }
            } else {
                printf("All 4 attempts failed. You need to try again later.\n");
            }
        }
    }
    for (int i = 0; i < MAX_PASSWORDS; i++) {
        free(passwords[i]);
    }

    return 0;
}
