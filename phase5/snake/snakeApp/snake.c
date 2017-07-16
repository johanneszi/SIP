/* Micro Snake, based on a simple simple snake game by Simon Huggins
 *
 * Copyright (c) 2003, 2004  Simon Huggins <webmaster@simonhuggins.com>
 * Copyright (c) 2009  Joachim Nilsson <troglobit@gmail.com>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * Original Borland Builder C/C++ snake code available at Simon's home page
 * http://www.simonhuggins.com/courses/cbasics/course_notes/snake.htm
 */

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>

#include "Enclave_u.h"
#include "sgx_utils/sgx_utils.h"

#include "conio.h"
#include "dir_utils.h"
#include "snake.h"

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

int sigsetup(int signo, void (*callback)(int)) {
    struct sigaction action;

    sigemptyset(&action.sa_mask);
    // sigaddset(&action.sa_mask, signo);
    action.sa_flags = 0;
    action.sa_handler = callback;
    if (SIGALRM == signo) {
#ifdef SA_INTERRUPT
        action.sa_flags |= SA_INTERRUPT; /* SunOS 4.x */
#endif
    } else {
#ifdef SA_RESTART
        action.sa_flags |= SA_RESTART; /* SVR4, 4.4BSD */
#endif
    }

    return sigaction(signo, &action, NULL);
}

void sig_handler(int signal __attribute__((unused))) {
    clrscr();
    DBG("Received signal %d\n", signal);
    exit(WEXITSTATUS(system("stty sane")));
}

void alarm_handler(int signal __attribute__((unused))) {
    static struct itimerval val;

    if (!signal) {
        sigsetup(SIGALRM, alarm_handler);
    }

    val.it_value.tv_sec = 0;

    int speed;
    sgx_status_t status = get_speed(global_eid, &speed);
    if (status != SGX_ERROR_INVALID_ENCLAVE_ID) {
        check_sgx_status(status, "Get speed failed!");
    }

    val.it_value.tv_usec = speed;

    setitimer(ITIMER_REAL, &val, NULL);
}

void show_score(screen_t *screen) {
    textcolor(LIGHTCYAN);
    gotoxy(3, MAXROW + 2);
    printf("Level: %05d", screen->level);

    textcolor(YELLOW);
    gotoxy(21, MAXROW + 2);
    printf("Gold Left: %05d", screen->gold);

    textcolor(LIGHTGREEN);
    gotoxy(43, MAXROW + 2);

    int score;
    sgx_status_t status = get_score(global_eid, &score);
    check_sgx_status(status, "Get score failed!");
    printf("Score: %05d", score);

    textcolor(LIGHTMAGENTA);
    gotoxy(61, MAXROW + 2);

    int high_score;
    status = get_high_score(global_eid, &high_score);
    check_sgx_status(status, "Get High score failed!");

    printf("High Score: %05d", high_score);
}

void draw_line(int col, int row) {
    int i;

    gotoxy(col, row);
    textbackground(LIGHTBLUE);
    textcolor(LIGHTBLUE);

    for (i = 0; i < MAXCOL + 2; i++) {
        if (i == 0 || i == MAXCOL + 1)
            printf("+");
        else
            printf("-");
    }

    textattr(RESETATTR);
}

/* If level==0 then just move on to the next level
 * if level==1 restart game
 * Otherwise start game at that level. */
void setup_level(screen_t *screen, snake_t *snake, int level) {
    int i, row, col;

    srand((unsigned int)time(NULL));

    /* Initialize on (re)start */
    if (1 == level) {
        sgx_status_t status = reset_score(global_eid);
        check_sgx_status(status, "Reset score failed!");

        screen->obstacles = 4;
        screen->level = 1;
        snake->dir = RIGHT;
    } else {
        sgx_status_t status = update_score_level(global_eid, screen->level);
        check_sgx_status(status, "Update score failed!");

        screen->obstacles += 2; /* add to obstacles */
        screen->level++;
    }

    /* Set up global variables for new level */
    screen->gold = 0;

    sgx_status_t status = set_length(global_eid, screen->level);
    check_sgx_status(status, "Could not set snake's length!");

    status = increase_speed(global_eid, screen->level);
    check_sgx_status(status, "Increase speed failed!");

    /* Fill grid with blanks */
    for (row = 0; row < MAXROW; row++) {
        for (col = 0; col < MAXCOL; col++) {
            screen->grid[row][col] = ' ';
        }
    }

    /* Fill grid with objects */
    for (i = 0; i < screen->obstacles * 2; i++) {
        /* Find free space to place an object on. */
        do {
            row = rand() % MAXROW;
            col = rand() % MAXCOL;
        } while (screen->grid[row][col] != ' ');

        if (i < screen->obstacles) {
            screen->grid[row][col] = CACTUS;
        } else {
            screen->gold++;
            screen->grid[row][col] = GOLD;
        }
    }

    /* Create snake array of length snake->len */
    int length;
    status = get_length(global_eid, &length);
    check_sgx_status(status, "Could not load length");

    for (i = 0; i < length; i++) {
        if (snake->dir == LEFT || snake->dir == RIGHT) {
            snake->body[i].row = START_ROW;
            snake->body[i].col = snake->dir == LEFT ? START_COL - i : START_COL + i;
        } else {
            snake->body[i].row = snake->dir == UP ? START_ROW - i : START_ROW + i;
            snake->body[i].col = START_COL;
        }
    }

    /* Draw playing board */
    clrscr();
    draw_line(1, 1);

    for (row = 0; row < MAXROW; row++) {
        gotoxy(1, row + 2);

        textcolor(LIGHTBLUE);
        textbackground(LIGHTBLUE);
        printf("|");
        textattr(RESETATTR);

        textcolor(WHITE);
        for (col = 0; col < MAXCOL; col++) {
            printf("%c", screen->grid[row][col]);
        }

        textcolor(LIGHTBLUE);
        textbackground(LIGHTBLUE);
        printf("|");
        textattr(RESETATTR);
    }

    draw_line(1, MAXROW + 2);

    show_score(screen);

    textcolor(LIGHTRED);
    // gotoxy (3, 1);
    // printf ("h:Help");
    gotoxy(30, 1);
    printf("[ Micro Snake v%s ]", VERSION);
}

void move(snake_t *snake, char keys[], char key) {
    int i;
    direction_t prev = snake->dir;

    if (key == keys[RIGHT]) {
        snake->dir = RIGHT;
    } else if (key == keys[LEFT]) {
        snake->dir = LEFT;
    } else if (key == keys[UP]) {
        snake->dir = UP;
    } else if (key == keys[DOWN]) {
        snake->dir = DOWN;
    } else if (key == keys[LEFT_TURN]) {
        switch (prev) {
            case LEFT:
                snake->dir = DOWN;
                break;

            case RIGHT:
                snake->dir = UP;
                break;

            case UP:
                snake->dir = LEFT;
                break;

            case DOWN:
                snake->dir = RIGHT;
                break;

            default:
                break;
        }
    } else if (key == keys[RIGHT_TURN]) {
        switch (prev) {
            case LEFT:
                snake->dir = UP;
                break;

            case RIGHT:
                snake->dir = DOWN;
                break;

            case UP:
                snake->dir = RIGHT;
                break;

            case DOWN:
                snake->dir = LEFT;
                break;

            default:
                break;
        }
    }

    int length;
    sgx_status_t status = get_length(global_eid, &length);
    check_sgx_status(status, "Could not load length");

    switch (snake->dir) {
        case LEFT:
            snake->body[length].row = snake->body[length - 1].row;
            snake->body[length].col = snake->body[length - 1].col - 1;
            break;

        case RIGHT:
            snake->body[length].row = snake->body[length - 1].row;
            snake->body[length].col = snake->body[length - 1].col + 1;
            break;

        case UP:
            snake->body[length].row = snake->body[length - 1].row - 1;
            snake->body[length].col = snake->body[length - 1].col;
            break;

        case DOWN:
            snake->body[length].row = snake->body[length - 1].row + 1;
            snake->body[length].col = snake->body[length - 1].col;
            break;

        default:
            /* NOP */
            break;
    }

    /* Blank last segment of snake */
    textattr(RESETATTR);
    gotoxy(snake->body[0].col + 1, snake->body[0].row + 1);
    puts(" ");

    /* ... and remove it from the array */
    for (i = 1; i <= length; i++) {
        snake->body[i - 1] = snake->body[i];
    }

    /* Display snake in yellow */
    textbackground(YELLOW);
    for (i = 0; i < length; i++) {
        gotoxy(snake->body[i].col + 1, snake->body[i].row + 1);
        puts(" ");
    }
    textattr(RESETATTR);
#ifdef DEBUG
    gotoxy(71, 1);
    printf("(%02d,%02d)", snake->body[length - 1].col, snake->body[length - 1].row);
#endif
}

int eat_gold(snake_t *snake, screen_t *screen) {
    int length;
    sgx_status_t status = get_length(global_eid, &length);
    check_sgx_status(status, "Could not load length");

    snake_segment_t *head = &snake->body[length - 1];

    /* We're called after collide_object() so we know it's
     * a piece of gold at this position.  Eat it up! */
    screen->grid[head->row - 1][head->col - 1] = ' ';

    screen->gold--;

    status = update_score_gold(global_eid, screen->obstacles);
    check_sgx_status(status, "Update score failed!");

    status = increase_length(global_eid);
    check_sgx_status(status, "Could not increase length");

    return screen->gold;
}

void save_high_score() {
    char secure_data[BUF_SIZE];

    relative_path_to(SECURE_DATA, secure_data, BUF_SIZE);

    sgx_status_t status = dump_high_score(global_eid, secure_data);
    check_sgx_status(status, "Dump High score failed!");
}

void load_old_high_score() {
    char secure_data[BUF_SIZE];

    relative_path_to(SECURE_DATA, secure_data, BUF_SIZE);

    sgx_status_t status = load_high_score(global_eid, secure_data);
    check_sgx_status(status, "Load High score failed!");
}

void init_enclave() {
    char enclave_token[BUF_SIZE];
    char enclave_signed[BUF_SIZE];

    relative_path_to("enclave.token", enclave_token, BUF_SIZE);
    relative_path_to("enclave.signed.so", enclave_signed, BUF_SIZE);

    if (initialize_enclave(&global_eid, enclave_token, enclave_signed) < 0) {
        fprintf(stderr, "Failed to initialize enclave.\n");
        exit(1);
    }
}

int main(void) {
    char keypress;
    snake_t snake;
    screen_t screen;
    char keys[NUM_KEYS] = DEFAULT_KEYS;

    init_enclave();
    load_old_high_score();

    if (WEXITSTATUS(system("stty cbreak -echo stop u"))) {
        fprintf(stderr, "Failed setting up the screen, is 'stty' missing?\n");
        return 1;
    }

    /* Call it once to initialize the timer. */
    alarm_handler(0);

    sigsetup(SIGINT, sig_handler);
    sigsetup(SIGHUP, sig_handler);
    sigsetup(SIGTERM, sig_handler);

    do {
        setup_level(&screen, &snake, 1);

        do {
            keypress = (char)getchar();

            /* Move the snake one position. */
            move(&snake, keys, keypress);

            /* keeps cursor flashing in one place instead of following snake */
            gotoxy(1, 1);
            int collided;
            sgx_status_t status = collision(global_eid, &collided, &snake, &screen);
            check_sgx_status(status, "Calling collision failed!");

            if (collided) {
                keypress = keys[QUIT];
                break;
            } else {
                int gold_eaten;
                status = collide_gold(global_eid, &gold_eaten, &snake, &screen);
                check_sgx_status(status, "Calling collide_gold failed!");

                if (gold_eaten) {
                    /* If no gold left after consuming this one... */
                    if (!eat_gold(&snake, &screen)) {
                        /* ... then go to next level. */
                        setup_level(&screen, &snake, 0);
                    }
                }

                show_score(&screen);
            }
        } while (keypress != keys[QUIT]);

        show_score(&screen);

        gotoxy(32, 6);
        textcolor(LIGHTRED);
        printf("-G A M E  O V E R-");

        gotoxy(32, 9);
        textcolor(YELLOW);
        printf("Another Game (y/n)? ");

        do {
            keypress = getchar();
        } while ((keypress != 'y') && (keypress != 'n'));
    } while (keypress == 'y');

    save_high_score();

    clrscr();

    if (destroy_enclave(global_eid) < 0) {
        fprintf(stderr, "Could not destroy Enclave %lu\n", global_eid);
    }

    return WEXITSTATUS(system("stty sane"));
}

/**
 * Local Variables:
 *  version-control: t
 *  c-file-style: "ellemtel"
 * End:
 */
