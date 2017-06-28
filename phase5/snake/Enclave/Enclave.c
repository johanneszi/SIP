#include "Enclave_t.h"

int high_score = 0;
int score = 0;
int length = 4;

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

void load_high_score(uint8_t* sealed_data, size_t sealed_size) {
    if (sealed_data == NULL)
        return;

    int unsealed;
    size_t unsealed_size = sizeof(unsealed);
    sgx_status_t status = sgx_unseal_data((sgx_sealed_data_t*) sealed_data,
            NULL, NULL, (uint8_t*) &unsealed, (uint32_t*) &unsealed_size);

    if (status != SGX_SUCCESS) {
        ocall_print("Loading not successful!", 0);
        return;
    }	

    ocall_print("Loaded High Score", unsealed);
    high_score = unsealed;
}

void dump_high_score(uint8_t *sealed_data, size_t sealed_size) {
    sgx_status_t status = sgx_seal_data(0, NULL, sizeof(high_score), (uint8_t*)&high_score,
                                        sealed_size, (sgx_sealed_data_t*)sealed_data);

    if (status != SGX_SUCCESS) {
        ocall_print("Storing not successful!", 0);
        return;
    }
}

int get_high_score() {
    return high_score += 20;
}

int get_score() {
    return score;
}

void update_score (screen_t *screen) {
    score += length * screen->obstacles;
    if (score > high_score) {
        high_score = score;
    }
}

void reset_score(){
    score = 0;
}

int get_length(){
    return length;
}

void increase_length(){
    length++;
}

void reset_length(){
    length = 4;
}
