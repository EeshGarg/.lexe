/* GDI: actual PIXELS, with an exact declared value.
 *
 * Every other GUI specimen here checks that a window existed and that messages
 * flowed. None of them checks that anything was DRAWN. This one renders into a
 * memory device context -- a 16x16 compatible bitmap -- fills it with a solid
 * brush of a known colour, and reads the pixel back with GetPixel.
 *
 * A COLORREF is 0x00BBGGRR, so RGB(0x10, 0x20, 0x30) is 0x00302010 and that number
 * is the declared result. It is one of the few end-to-end rendering assertions that
 * can be made without a screenshot: if the blit, the brush or the colour conversion
 * is wrong, the number is wrong, and if the drawing never happened at all the
 * number is the background.
 *
 * A second rectangle in a different colour is drawn beside the first, so a
 * implementation that fills the whole surface with the last brush is caught too,
 * and the boundary between them is checked on both sides.
 */
#include "oracle_win.h"

#define W 16
#define H 16
#define COL_A RGB(0x10, 0x20, 0x30)
#define COL_B RGB(0xC0, 0x40, 0x80)

int WINAPI WinMain(HINSTANCE inst, HINSTANCE prev, LPSTR cmd, int show) {
    HDC screen, mem;
    HBITMAP bmp, oldbmp;
    HBRUSH brush_a, brush_b;
    RECT left, right;
    COLORREF a, b, edge_a, edge_b;
    (void)inst; (void)prev; (void)cmd; (void)show;
    orc_begin("pe-gui-gdi-pixels");

    screen = GetDC(NULL);
    orc_check("GET_DC", screen != NULL);
    if (!screen) { orc_werr_now("GET_DC_ERROR"); return orc_end(); }
    orc_obs("SCREEN_BITS_PER_PIXEL", "%d", GetDeviceCaps(screen, BITSPIXEL));
    orc_obs("SCREEN_WIDTH", "%d", GetDeviceCaps(screen, HORZRES));

    mem = CreateCompatibleDC(screen);
    orc_check("CREATE_COMPATIBLE_DC", mem != NULL);
    bmp = CreateCompatibleBitmap(screen, W, H);
    orc_check("CREATE_COMPATIBLE_BITMAP", bmp != NULL);
    if (!mem || !bmp) { orc_werr_now("GDI_CREATE_ERROR"); return orc_end(); }
    oldbmp = (HBITMAP)SelectObject(mem, bmp);

    brush_a = CreateSolidBrush(COL_A);
    brush_b = CreateSolidBrush(COL_B);
    orc_check("CREATE_BRUSHES", brush_a != NULL && brush_b != NULL);

    left.left = 0;  left.top = 0;  left.right = 8;  left.bottom = H;
    right.left = 8; right.top = 0; right.right = W; right.bottom = H;
    orc_check("FILL_LEFT", FillRect(mem, &left, brush_a) != 0);
    orc_check("FILL_RIGHT", FillRect(mem, &right, brush_b) != 0);

    a = GetPixel(mem, 4, 8);
    b = GetPixel(mem, 12, 8);
    edge_a = GetPixel(mem, 7, 0);
    edge_b = GetPixel(mem, 8, 0);
    orc_kv("PIXEL_LEFT", "0x%08lx", (unsigned long)a);
    orc_kv("PIXEL_RIGHT", "0x%08lx", (unsigned long)b);
    orc_kv("PIXEL_LEFT_EDGE", "0x%08lx", (unsigned long)edge_a);
    orc_kv("PIXEL_RIGHT_EDGE", "0x%08lx", (unsigned long)edge_b);
    orc_kv("EXPECTED_LEFT", "0x%08lx", (unsigned long)COL_A);
    orc_kv("EXPECTED_RIGHT", "0x%08lx", (unsigned long)COL_B);
    orc_check("LEFT_HALF_IS_THE_COLOUR_IT_WAS_PAINTED", a == COL_A);
    orc_check("RIGHT_HALF_IS_THE_COLOUR_IT_WAS_PAINTED", b == COL_B);
    orc_check("THE_BOUNDARY_IS_EXACTLY_WHERE_IT_WAS_ASKED_FOR",
              edge_a == COL_A && edge_b == COL_B);

    /* SetPixel and read back: a different entry point to the same surface. */
    orc_check("SET_PIXEL", SetPixel(mem, 1, 1, RGB(0xFF, 0xFF, 0xFF)) != (COLORREF)-1);
    orc_kv("PIXEL_AFTER_SET", "0x%08lx", (unsigned long)GetPixel(mem, 1, 1));
    orc_check("SET_PIXEL_TOOK_EFFECT", GetPixel(mem, 1, 1) == RGB(0xFF, 0xFF, 0xFF));

    /* And the bits straight out of the bitmap, bypassing GetPixel entirely. */
    {
        BITMAPINFO bi;
        unsigned char *pixels = (unsigned char *)malloc((size_t)W * H * 4);
        ZeroMemory(&bi, sizeof bi);
        bi.bmiHeader.biSize = sizeof bi.bmiHeader;
        bi.bmiHeader.biWidth = W;
        bi.bmiHeader.biHeight = -H;            /* top-down */
        bi.bmiHeader.biPlanes = 1;
        bi.bmiHeader.biBitCount = 32;
        bi.bmiHeader.biCompression = BI_RGB;
        SelectObject(mem, oldbmp);
        if (pixels && GetDIBits(mem, bmp, 0, H, pixels, &bi, DIB_RGB_COLORS) == H) {
            /* Row 8, column 4: BGRA. */
            const unsigned char *px = pixels + (8 * W + 4) * 4;
            orc_check("GET_DI_BITS", 1);
            orc_kv("DIB_PIXEL_BGR", "%02x%02x%02x", px[0], px[1], px[2]);
            orc_check("DIB_AGREES_WITH_GETPIXEL",
                      px[0] == 0x30 && px[1] == 0x20 && px[2] == 0x10);
        } else {
            orc_check("GET_DI_BITS", 0);
        }
        free(pixels);
        SelectObject(mem, bmp);
    }

    SelectObject(mem, oldbmp);
    DeleteObject(brush_a);
    DeleteObject(brush_b);
    DeleteObject(bmp);
    DeleteDC(mem);
    ReleaseDC(NULL, screen);
    orc_check("PIXELS_WERE_REALLY_RENDERED", 1);
    return orc_end();
}
