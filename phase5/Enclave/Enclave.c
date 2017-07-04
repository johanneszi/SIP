#include "Enclave_t.h"
#include "snake.h"
#include "sgx_stdio.h"

int high_score = 0;
int score = 0;
int length = START_LEN;
int speed = DEFAULT_DELAY;

int collide_walls(snake_t *snake) {
    snake_segment_t *head = &snake->body[length - 1];

    if ((head->row > MAXROW) || (head->row < 1) ||
        (head->col > MAXCOL) || (head->col < 1)) {
        DBG("Wall collision.\n");
        return 1;
    }

    return 0;
}

int collide_object(snake_t *snake, screen_t *screen, char object) {
    snake_segment_t *head = &snake->body[length - 1];

    if (screen->grid[head->row - 1][head->col - 1] == object) {
        DBG("Object '%c' collision.\n", object);
        return 1;
    }

    return 0;
}

int collide_gold(snake_t *snake, screen_t *screen) {
    return collide_object(snake, screen, GOLD);
}

int collide_self(snake_t *snake) {
    int i;
    snake_segment_t *head = &snake->body[length - 1];

    for (i = 0; i < length - 1; i++) {
        snake_segment_t *body = &snake->body[i];

        if (head->row == body->row && head->col == body->col) {
            DBG("Self collision.\n");
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

void load_high_score(const char *filename) {
    int fd, unsealed;
    size_t unsealed_size = sizeof(unsealed);
    size_t sealed_size = sizeof(sgx_sealed_data_t) + unsealed_size;
    uint8_t* sealed_data = NULL;

    // Try to read sealed old high_score
    if ((fd = open(filename, O_RDONLY, S_IRWXU)) == -1) {
        fprintf(stderr, "Could not load secure data file! Is the file already created?\n");
        return;
    }

    sealed_data = (uint8_t*) malloc(sealed_size);
    if (read(fd, sealed_data, sealed_size) != sealed_size) {
        fprintf(stderr, "Could not read secure data!\n");
        free(sealed_data);
        return;
    }

    // Try to unseal it (It may fail for example if the old high_score
    // was not sealed by the same enclave)
    sgx_status_t status = sgx_unseal_data((sgx_sealed_data_t*) sealed_data,
            NULL, NULL, (uint8_t*) &unsealed, (uint32_t*) &unsealed_size);

    free(sealed_data);
    close(fd);

    if (status != SGX_SUCCESS) {
        fprintf(stderr, "Loading high score not successful!\n");
        return;
    }

    DBG("Loaded High Score: [%d]\n", unsealed);
    high_score = unsealed;
}

void dump_high_score(const char *filename) {
    int fd;
    size_t sealed_size = sizeof(sgx_sealed_data_t) + sizeof(high_score);
    uint8_t *sealed_data = (uint8_t*) malloc(sealed_size);

    // Seal high_score and save it in sealed_data
    sgx_status_t status = sgx_seal_data(0, NULL, sizeof(high_score), (uint8_t*) &high_score,
                                        sealed_size, (sgx_sealed_data_t*) sealed_data);

    if (status != SGX_SUCCESS) {
        fprintf(stderr, "Storing high score not successful!\n");
        free(sealed_data);
        return;
    }

    // Write the sealed high_score to file
    if ((fd = open(filename, (O_CREAT | O_WRONLY | O_TRUNC), S_IRWXU)) == -1) {
        fprintf(stderr, "Could not load file to write!\n");
        free(sealed_data);
        return;
    }

    if (write(fd, sealed_data, sealed_size) != sealed_size) {
        fprintf(stderr, "Could not write!\n");
        free(sealed_data);
        return;
    }

    free(sealed_data);
    close(fd);
}

int get_high_score() {
    return high_score;
}

int get_score() {
    return score;
}

void update_score_gold(int obstacles) {
    score += length * obstacles;
    if (score > high_score) {
        high_score = score;
    }
}

void update_score_level(int level) {
    score += level * 1000;
    if (score > high_score) {
        high_score = score;
    }
}

void reset_score() {
    score = 0;
}

int get_length() {
    return length;
}

void increase_length() {
    // Increase length only if there is enough space for more segments
    if (length < MAX_LEN) {
        length++;
    }
}

void set_length(int level) {
    // Initialise length but don't be outside the grid in the beginning
    int newLength = level + START_LEN;
    length = fmin(fmin(newLength, MAX_LEN), MAXROW / 2 - 2);
}

void increase_speed(int level) {
    // Increase speed but never more than DEFAULT_DELAY / 3
    int new_speed = DEFAULT_DELAY - level * 1000;
    speed = new_speed < (DEFAULT_DELAY / 3) ? DEFAULT_DELAY / 3 : new_speed;
}

int get_speed() {
    return speed;
}
