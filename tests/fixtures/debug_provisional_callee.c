/* Original fixture: a callee whose declared 32-bit parameters (`offset`,
 * `columns`, `rows`) leave register upper halves live, and whose calls go to
 * external functions without known prototypes. Built as a shared object with
 * hidden visibility, so `energy_maps` calls `grid_energy` directly. Its
 * unlocked inputs agree with the debug prototype, but the locked render
 * passes the upper halves to `pool_take` as invented extra arguments. */
#include <stdio.h>
#include <string.h>

struct grid {
    int count, width, height;
    int **offsets;
};

struct waves {
    int count, length;
    double **values;
};

extern void *pool_take(unsigned long size);
extern void pool_give(void *block);

__attribute__((noinline)) void add_rows(int *sums, const unsigned char *block,
                                        const int *offsets, int width)
{
    for (int i = 0; i < width; i++)
        sums[i] += block[offsets[i]];
}

__attribute__((noinline)) void wave_energy(double *out, const int *sums, const double *wave,
                                           int length)
{
    double total = 0;
    for (int i = 0; i < length; i++)
        total += sums[i] * wave[i];
    *out = total;
}

__attribute__((noinline)) int grid_energy(double **energy, unsigned char *pixels, const int offset,
                                          const int columns, const int rows,
                                          const struct waves *waves, const struct grid *grid)
{
    if (grid->width != grid->height) {
        fprintf(stderr, "grid_energy: the grid must be square\n");
        return -90;
    }
    int *sums = pool_take(grid->width * sizeof(int));
    memset(sums, 0, grid->width * sizeof(int));
    unsigned char *block = pixels + offset;
    for (int g = 0; g < grid->count; g++) {
        add_rows(sums, block, grid->offsets[g], grid->width);
        for (int w = 0; w < waves->count; w++)
            wave_energy(&energy[w][g], sums, waves->values[w], waves->length);
    }
    pool_give(sums);
    return 0;
}

int energy_maps(double **energy, unsigned char *pixels, int columns, int rows,
                const struct waves *waves, const struct grid *grid)
{
    int status = 0;
    for (int y = 0; y + 8 <= rows && !status; y += 8)
        for (int x = 0; x + 8 <= columns && !status; x += 8)
            status = grid_energy(energy, pixels, y * columns + x, columns, rows, waves, grid);
    return status;
}
