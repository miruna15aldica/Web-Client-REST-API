#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netdb.h>      
#include <unistd.h>      
#include <sys/socket.h> 
#include <string.h>
#include <netinet/in.h> 
#include <stdio.h>
#include <stdlib.h>  
#include <ctype.h>
#include "buffer.h"
#include "helpers.h"
#include "requests.h"
#define REGISTER "/api/v1/tema/auth/register"
#define LOGIN "/api/v1/tema/auth/login"
#define LOGOUT "/api/v1/tema/auth/logout"
#define ENTER_LIBRARY "/api/v1/tema/library/access"
#define ADD_BOOK "/api/v1/tema/library/books"
#define GET_BOOK "/api/v1/tema/library/books/"
#define JSON "application/json"
#define PORT 8080
#define HOST "34.254.242.81"

int main() {
    int sockfd;
    char buf[1000];
    char *url_address = calloc(LINELEN, sizeof(char));
    char *token = calloc(4096, sizeof(char));
    char *session = calloc(4096, sizeof(char));
    
    while(1) {
        fgets(buf, 1000, stdin);
        
        buf[strlen(buf) - 1] = '\0';
        if(!strncmp(buf, "exit", 4)) {
            break;
        } else if(!strncmp(buf, "register", 8)){
            char username[1000];
            char password[1000];
            printf("username=");
            scanf("%[^\n]%*c", username);
            char *username_helper = strtok(username, "\n");
            printf("password=");
            scanf("%[^\n]%*c", password);
            char *password_helper = strtok(password, "\n");
            sockfd = open_connection(HOST, PORT, AF_INET, SOCK_STREAM, 0);
            char *helper = calloc(4096, sizeof(char));
            memset(helper, 0, 4096);
            sprintf(helper, "{\n\t\"username\":\"%s\",\n\t\"password\":\"%s\"\n}", username_helper, password_helper);
            char *server_response;
            char *request = compute_post_request(HOST, REGISTER, JSON, &helper, 1, NULL, 0);
            send_to_server(sockfd, request);
            server_response = receive_from_server(sockfd);
            char *c = strtok(server_response, "\n\r");
            if (c[9] == '2')
            {
                printf("Registered with succes!\n");   
            }
            else
            {
                 printf("Username already taken. Please try again!\n");
            }
        } else if(!strncmp(buf, "login", 6)) {
            // if(strlen(session) > 0) {
            //     printf("You are already connected!\n");
            //     continue;
            // }
            char username[1000];
            char password[1000];
            printf("username=");
            scanf("%[^\n]%*c", username);
            char *username_helper = strtok(username, "\n");
            printf("password=");
            scanf("%[^\n]%*c", password);
            char *password_helper = strtok(password, "\n");
            sockfd = open_connection(HOST, PORT, AF_INET, SOCK_STREAM, 0);
            char *helper = calloc(4096, sizeof(char));
            memset(helper, 0, 4096);
            sprintf(helper, "{\n\t\"username\":\"%s\",\n\t\"password\":\"%s\"\n}", username_helper, password_helper);
            char *request  = compute_post_request(HOST, LOGIN, JSON, &helper, 1, NULL, 0);
            send_to_server(sockfd, request);
            char *server_response;
            server_response = receive_from_server(sockfd);
            char *review = strstr(server_response, "Cookie");
            char *copy = strdup(server_response);
            copy = strtok(copy, "\n");
            if(copy[9] != '2') {
                printf("Wrong username or password. Please try again!\n");
            }
            
            if(review == NULL) {
                continue;
            }
            review = strtok(review, ";");
            printf("Congratulations! You are logged in!\n");
            memset(session, 0, 4096);
            strcpy(session, review + 8);
        } else if(!strncmp(buf, "logout", 6)) {
            sockfd = open_connection(HOST, PORT, AF_INET, SOCK_STREAM, 0);
            char *request = compute_get_request(HOST, LOGOUT, NULL, &session, 1);
            send_to_server(sockfd, request);
            char *server_response;
            server_response = receive_from_server(sockfd);
            switch(server_response[9]) {
                case '2':
                    memset(session, 0, 4096);
                    memset(token, 0, 4096);
                    printf("You succesfully logged out!\n");
                    break;
                case '4': 
                    printf("Impossible command. You are not logged in!\n");
                    break;
                
                default:
                    printf("An error has occured. Please, try again!\n");
                    break;
            }   
        } else if(!strncmp(buf, "enter_library", 13)) {
            if(strlen(session) == 0) {
                printf("You MUST be logged in for entering the library!\n");
                continue;
            }
            sockfd = open_connection(HOST, PORT, AF_INET, SOCK_STREAM, 0);
            char *request = compute_get_request(HOST, ENTER_LIBRARY, NULL, &session, 1);
            send_to_server(sockfd, request);
            char *server_response;
            server_response = receive_from_server(sockfd);
            char *r = strstr(server_response, "token");
            if (r == NULL)
            {
                printf("An error has occured!\n");
                continue;
            }
            memset(token, 0, 4096);
            r = r + 8;
            strcpy(token, strtok(r,"\"" ));
            switch(strlen(token)) {
                case 0:
                    printf("An error has occured\n");
                    break;
                default:
                    printf("You succesfully entered the library!\n");
                    break;

            }
        } else if(!strncmp(buf, "add_book", 8)) {
            sockfd = open_connection(HOST, PORT, AF_INET, SOCK_STREAM, 0);
            if (strlen(token) == 0)
            {
                printf("You don't have access\n");
                continue;
            }
            char title[200], author[200], genre[200], page_count[200], publisher[200];
            printf("title=");
            scanf("%[^\n]%*c", title);
            char *title_helper = strtok(title, "\n");
            printf("author=");
            scanf("%[^\n]%*c", author);
            char *author_helper = strtok(author, "\n");
            printf("genre=");
            scanf("%[^\n]%*c", genre);
            char *genre_helper = strtok(genre, "\n");
            printf("publisher=");
            scanf("%[^\n]%*c", publisher);
            char *publisher_helper = strtok(publisher, "\n");
            printf("page_count=");
            scanf("%[^\n]%*c", page_count);
            char *page_count_helper = strtok(page_count, "\n");
            char *helper = calloc(4096, sizeof(char));
            memset(helper, 0, BUFLEN);
            int verify = 0;
            int i = 0;
            while(i < strlen(page_count_helper)) {
                if (page_count_helper[i] < '0' || page_count_helper[i] > '9')
                {
                    printf("Invalid page count!!!\n");
                    verify = 1;
                    break;
                }
                i++;
            }
            if (verify)
            {
                continue;
            }
            snprintf(helper, BUFLEN, "{\n\t\"title\":\"%s\",\n\t\"author\":\"%s\",\n\t\"genre\":\"%s\",\n\t\"page_count\":\"%s\",\n\t\"publisher\":\"%s\"\n}",
            title_helper, author_helper, genre_helper, page_count_helper, publisher_helper);
            
            char *message = calloc(BUFLEN, sizeof(char));
            char *line = calloc(LINELEN, sizeof(char));
            char *body_data_buffer = calloc(LINELEN, sizeof(char));
            sprintf(line, "POST %s HTTP/1.1", ADD_BOOK);
            // secventa de cod preluata din cadrul laboratorului
            compute_message(message, line);
            sprintf(line, "Host: %s", HOST);
            compute_message(message, line);
            if(token != NULL)
            {
                memset(line, 0, LINELEN);
                strcpy(line, "Authorization: Bearer ");
                strcat(line, token);
                compute_message(message, line);
                memset(line, 0, LINELEN);
            }
            memset(body_data_buffer, 0, LINELEN);
            for (int i = 0; i < 1; ++i) {
                strcat(body_data_buffer, &helper[i]);
                if (i != 0) {
                    strcat(body_data_buffer, "&");
                }
            }
            sprintf(line, "Content-Type: %s", JSON);
            compute_message(message, line);
  
            sprintf(line, "Content-Length: %lu", strlen(body_data_buffer));
            compute_message(message, line);
            compute_message(message, "");
            memset(line, 0, LINELEN);
            strcat(message, body_data_buffer);

            free(line);
            free(body_data_buffer);
            send_to_server(sockfd, message);
            char *server_response;
            server_response = receive_from_server(sockfd);
            printf("The book was succesfully added!\n");
        } else if(!strncmp(buf, "get_books", 9)) {
            sockfd = open_connection(HOST, PORT, AF_INET, SOCK_STREAM, 0);
            if(!strlen(token)) {
                printf("You do not have access to the books.\n");
                continue;
            }
            char *message = calloc(BUFLEN, sizeof(char));
            char *line = calloc(LINELEN, sizeof(char));
            sprintf(line, "GET %s HTTP/1.1", ADD_BOOK);
            compute_message(message, line);
            sprintf(line, "Host: %s", HOST);
            compute_message(message, line);
            if(token != NULL)
            {
                memset(line, 0, LINELEN);
                strcpy(line, "Authorization: Bearer ");
                strcat(line, token);
                compute_message(message, line);
            }
            compute_message(message, "");
            free(line);
            send_to_server(sockfd, message);
            char *server_response;
            server_response = receive_from_server(sockfd);
            char *content = strstr(server_response, "[");
            if(content == NULL) {
                printf("An error has occured!\n");
                continue;
            }
            printf("%s\n", content);
        }  else if(!strncmp(buf, "get_book", 8)) {
            if (strlen(token) == 0)
            {
                printf("You don't have access\n");
                continue;
            }
            
            sockfd = open_connection(HOST, PORT, AF_INET, SOCK_STREAM, 0);
            printf("id=");
            char id[1000]; 
            fgets(id, 1000, stdin);
            memset(url_address, 0, 1000);
            strcpy(url_address, GET_BOOK);
            strcat(url_address, id);
            url_address = strtok(url_address, "\n");
            

            char *message = calloc(BUFLEN, sizeof(char));
            char *line = calloc(LINELEN, sizeof(char));
            sprintf(line, "GET %s HTTP/1.1", url_address);
            compute_message(message, line);
            sprintf(line, "Host: %s", HOST);
            compute_message(message, line);

            if(token != NULL)
            {
                memset(line, 0, LINELEN);
                strcpy(line, "Authorization: Bearer ");
                strcat(line, token);
                compute_message(message, line);
            }
            compute_message(message, "");
            free(line);
            send_to_server(sockfd, message);
            char *response;
            response = receive_from_server(sockfd);
            char *show = strrchr(response, '{');
            show = strtok(show, "]");
            if(show == NULL) {
                printf("An error has occured. The ID is not correct.\n");
            } else {
                printf("%s\n", show);
            }
            
        } else if(!strncmp(buf, "delete_book", 11)) {
            if (strlen(token) == 0)
            {
                printf("You don't have access\n");
                continue;
            }
            sockfd = open_connection(HOST, PORT, AF_INET, SOCK_STREAM, 0);
            printf("id=");
            char id[1000]; 
            fgets(id, 1000, stdin);
            memset(url_address, 0, 1000);
            strcpy(url_address, GET_BOOK);
            strcat(url_address, id);
            url_address = strtok(url_address, "\n");
            char *message = calloc(BUFLEN, sizeof(char));
            char *line = calloc(LINELEN, sizeof(char));
            sprintf(line, "GET %s HTTP/1.1", url_address);
            compute_message(message, line);
            sprintf(line, "Host: %s", HOST);
            compute_message(message, line);

            if(token != NULL)
            {
                memset(line, 0, LINELEN);
                strcpy(line, "Authorization: Bearer ");
                strcat(line, token);
                compute_message(message, line);
            }
            char *str = calloc(4096, sizeof(char));
            compute_message(message, "");
            char *server_respunse;
            free(line);
            message = message + 3;
            strcpy(str, "DELETE");
            strcat(str, message);
            send_to_server(sockfd, str);
            server_respunse = receive_from_server(sockfd);
            switch(server_respunse[9]) {
                case '4':
                    printf("Invalid ID. Please try again!\n");
                    break;
                case '2':
                    printf("The book was succesfully deleted.\n");
                    break;
                default:
                    printf("An error has occured.\n");
            }
        } else {
            printf("Unknown command. Please try again!");
        }
        close_connection(sockfd);

    }
    free(url_address);
    free(token);
    free(session);
    return 0;
}
    