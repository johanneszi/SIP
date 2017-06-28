#include "Enclave_t.h"

int collide_walls(snake_t *snake) {
    snake_segment_t *head = &snake->body[snake->len - 1];

    if ((head->row > MAXROW) || (head->row < 1) ||
        (head->col > MAXCOL) || (head->col < 1)) {
        return 1;
    }

    return 0;
}

int collide_object(snake_t *snake, screen_t *screen, char object) {
    snake_segment_t *head = &snake->body[snake->len - 1];

    if (screen->grid[head->row - 1][head->col - 1] == object) {
        return 1;
    }

    return 0;
}

int collide_gold(snake_t *snake, screen_t *screen) {
    return collide_object(snake, screen, GOLD);
}

int collide_self(snake_t *snake) {
    int i;
    snake_segment_t *head = &snake->body[snake->len - 1];

    for (i = 0; i < snake->len - 1; i++) {
        snake_segment_t *body = & snake->body[i];

        if (head->row == body->row && head->col == body->col) {
            return 1;
        }
    }

    return 0;
}

int collision(snake_t *snake, screen_t *screen) {
    return collide_walls(snake) ||
        collide_object(snake, screen, CACTUS) ||
        collide_self(snake);
}
