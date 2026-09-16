/*
 * RinOS product globalization backend.
 *
 * This file intentionally does not include ICU headers.  The RinOS target
 * binds System.Globalization.Native to the product-owned rinicud service and
 * never to the build host's ICU installation.  The service ABI is UTF-8;
 * CoreCLR's PAL ABI is UTF-16, so conversion is kept at this boundary.
 */

#include <stddef.h>
#include <stdint.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "../../../../../../public-base/libs/rinicu/include/rinicu/rinicu.h"
#include "../../../../../../public-base/libs/rinicu/include/rinicu/data_policy.h"
#include "../../../../../../public-base/libs/libunicode/rin_unicode.h"

typedef uint16_t UChar;

typedef enum
{
    Success = 0,
    UnknownError = 1,
    InsufficientBuffer = 2,
    OutOfMemory = 3,
    InvalidCodePoint = 4
} ResultCode;

typedef uint16_t CalendarId;
typedef void (*EnumCalendarInfoCallback)(const UChar*, const void*);

typedef enum
{
    CalendarData_Uninitialized = 0,
    CalendarData_NativeName = 1,
    CalendarData_MonthDay = 2,
    CalendarData_ShortDates = 3,
    CalendarData_LongDates = 4,
    CalendarData_YearMonths = 5,
    CalendarData_DayNames = 6,
    CalendarData_AbbrevDayNames = 7,
    CalendarData_MonthNames = 8,
    CalendarData_AbbrevMonthNames = 9,
    CalendarData_SuperShortDayNames = 10,
    CalendarData_MonthGenitiveNames = 11,
    CalendarData_AbbrevMonthGenitiveNames = 12,
    CalendarData_EraNames = 13,
    CalendarData_AbbrevEraNames = 14
} CalendarDataType;

typedef enum
{
    LocaleString_LocalizedDisplayName = 0x02,
    LocaleString_EnglishDisplayName = 0x00000072,
    LocaleString_NativeDisplayName = 0x00000073,
    LocaleString_LocalizedLanguageName = 0x0000006f,
    LocaleString_EnglishLanguageName = 0x00001001,
    LocaleString_NativeLanguageName = 0x04,
    LocaleString_EnglishCountryName = 0x00001002,
    LocaleString_NativeCountryName = 0x08,
    LocaleString_DecimalSeparator = 0x0E,
    LocaleString_ThousandSeparator = 0x0F,
    LocaleString_Digits = 0x00000013,
    LocaleString_MonetarySymbol = 0x00000014,
    LocaleString_CurrencyEnglishName = 0x00001007,
    LocaleString_CurrencyNativeName = 0x00001008,
    LocaleString_Iso4217MonetarySymbol = 0x00000015,
    LocaleString_MonetaryDecimalSeparator = 0x00000016,
    LocaleString_MonetaryThousandSeparator = 0x00000017,
    LocaleString_AMDesignator = 0x00000028,
    LocaleString_PMDesignator = 0x00000029,
    LocaleString_PositiveSign = 0x00000050,
    LocaleString_NegativeSign = 0x00000051,
    LocaleString_Iso639LanguageTwoLetterName = 0x00000059,
    LocaleString_Iso639LanguageThreeLetterName = 0x00000067,
    LocaleString_Iso3166CountryName = 0x0000005A,
    LocaleString_Iso3166CountryName2 = 0x00000068,
    LocaleString_NaNSymbol = 0x00000069,
    LocaleString_PositiveInfinitySymbol = 0x0000006a,
    LocaleString_NegativeInfinitySymbol = 0x0000006b,
    LocaleString_ParentName = 0x0000006d,
    LocaleString_PercentSymbol = 0x00000076,
    LocaleString_PerMilleSymbol = 0x00000077
} LocaleStringData;

typedef enum
{
    LocaleNumber_LanguageId = 0x01,
    LocaleNumber_MeasurementSystem = 0x0D,
    LocaleNumber_FractionalDigitsCount = 0x00000011,
    LocaleNumber_NegativeNumberFormat = 0x00001010,
    LocaleNumber_MonetaryFractionalDigitsCount = 0x00000019,
    LocaleNumber_PositiveMonetaryNumberFormat = 0x0000001B,
    LocaleNumber_NegativeMonetaryNumberFormat = 0x0000001C,
    LocaleNumber_FirstDayofWeek = 0x0000100C,
    LocaleNumber_FirstWeekOfYear = 0x0000100D,
    LocaleNumber_ReadingLayout = 0x00000070,
    LocaleNumber_NegativePercentFormat = 0x00000074,
    LocaleNumber_PositivePercentFormat = 0x00000075,
    LocaleNumber_Digit = 0x00000010,
    LocaleNumber_Monetary = 0x00000018
} LocaleNumberData;

typedef enum
{
    FormC = 0x1,
    FormD = 0x2,
    FormKC = 0x5,
    FormKD = 0x6
} NormalizationForm;

typedef enum
{
    TimeZoneDisplayName_Generic = 0,
    TimeZoneDisplayName_Standard = 1,
    TimeZoneDisplayName_DaylightSavings = 2,
    TimeZoneDisplayName_GenericLocation = 3,
    TimeZoneDisplayName_ExemplarCity = 4,
    TimeZoneDisplayName_TimeZoneName = 5
} TimeZoneDisplayNameType;

typedef struct SortHandle
{
    rin_icu_client_t* client;
    rin_icu_handle_t handle;
} SortHandle;

typedef struct RinJapaneseEra
{
    int32_t start_year;
    int32_t start_month;
    int32_t start_day;
} RinJapaneseEra;

/* JapaneseCalendar era numbers are stable historical data, not a host ICU
 * probe.  ICU uses zero-based era indices from Meiji through Reiwa.  A future
 * era is an explicit product data update; it must not be guessed from
 * wall-clock time. */
static const RinJapaneseEra g_japanese_eras[] = {
    { 1868, 9, 8 },   /* Meiji */
    { 1912, 7, 30 },  /* Taisho */
    { 1926, 12, 25 }, /* Showa */
    { 1989, 1, 8 },   /* Heisei */
    { 2019, 5, 1 },   /* Reiwa */
};

static const char* const g_japanese_era_names[] = {
    "明治", "大正", "昭和", "平成", "令和"
};

static const char* const g_japanese_era_abbreviations[] = {
    "M", "T", "S", "H", "R"
};

static rin_icu_client_t g_client = {};

static rin_icu_client_t* product_client(void)
{
    if (!rin_icu_client_is_open(&g_client)) {
        rin_icu_client_init(&g_client);
    }
    if (!rin_icu_client_is_open(&g_client) &&
        rin_icu_client_open(&g_client) != RIN_ICU_STATUS_OK) {
        return NULL;
    }
    return &g_client;
}

static size_t u16_length(const UChar* value, int32_t length)
{
    size_t result = 0u;
    if (!value) return 0u;
    if (length >= 0) return (size_t)length;
    while (value[result] != 0u) ++result;
    return result;
}

static int append_utf8(char* dest, size_t capacity, size_t* length, uint32_t cp)
{
    size_t at = *length;
    if (cp <= 0x7fu) {
        if (at + 1u >= capacity) return 0;
        dest[at++] = (char)cp;
    } else if (cp <= 0x7ffu) {
        if (at + 2u >= capacity) return 0;
        dest[at++] = (char)(0xc0u | (cp >> 6));
        dest[at++] = (char)(0x80u | (cp & 0x3fu));
    } else if (cp <= 0xffffu) {
        if (at + 3u >= capacity) return 0;
        dest[at++] = (char)(0xe0u | (cp >> 12));
        dest[at++] = (char)(0x80u | ((cp >> 6) & 0x3fu));
        dest[at++] = (char)(0x80u | (cp & 0x3fu));
    } else if (cp <= 0x10ffffu) {
        if (at + 4u >= capacity) return 0;
        dest[at++] = (char)(0xf0u | (cp >> 18));
        dest[at++] = (char)(0x80u | ((cp >> 12) & 0x3fu));
        dest[at++] = (char)(0x80u | ((cp >> 6) & 0x3fu));
        dest[at++] = (char)(0x80u | (cp & 0x3fu));
    } else {
        return 0;
    }
    *length = at;
    return 1;
}

static char* utf16_to_utf8(const UChar* value, int32_t value_length, size_t* out_length)
{
    size_t length;
    size_t capacity;
    size_t at = 0u;
    char* result;
    size_t i;
    if (!value) return NULL;
    length = u16_length(value, value_length);
    if (length > (SIZE_MAX - 1u) / 4u) return NULL;
    capacity = length * 4u + 1u;
    result = (char*)malloc(capacity);
    if (!result) return NULL;
    for (i = 0u; i < length; ++i) {
        uint32_t cp = value[i];
        if (cp >= 0xd800u && cp <= 0xdbffu) {
            if (i + 1u >= length || value[i + 1u] < 0xdc00u || value[i + 1u] > 0xdfffu) {
                free(result);
                return NULL;
            }
            cp = 0x10000u + ((cp - 0xd800u) << 10) + (value[++i] - 0xdc00u);
        } else if (cp >= 0xdc00u && cp <= 0xdfffu) {
            free(result);
            return NULL;
        }
        if (!append_utf8(result, capacity, &at, cp)) {
            free(result);
            return NULL;
        }
    }
    result[at] = '\0';
    if (out_length) *out_length = at;
    return result;
}

static int decode_utf8(const unsigned char* source, size_t length, size_t* offset, uint32_t* out)
{
    uint32_t cp;
    size_t need;
    size_t sequence_length;
    unsigned char first;
    if (*offset >= length) return 0;
    first = source[(*offset)++];
    if (first < 0x80u) {
        *out = first;
        return 1;
    }
    if (first >= 0xc2u && first <= 0xdfu) {
        cp = first & 0x1fu;
        need = 1u;
    } else if (first >= 0xe0u && first <= 0xefu) {
        cp = first & 0x0fu;
        need = 2u;
    } else if (first >= 0xf0u && first <= 0xf4u) {
        cp = first & 0x07u;
        need = 3u;
    } else {
        return 0;
    }
    sequence_length = need;
    if (*offset + need > length) return 0;
    while (need-- > 0u) {
        unsigned char continuation = source[(*offset)++];
        if ((continuation & 0xc0u) != 0x80u) return 0;
        cp = (cp << 6) | (continuation & 0x3fu);
    }
    if (cp > 0x10ffffu || (cp >= 0xd800u && cp <= 0xdfffu) ||
        (sequence_length == 1u && cp < 0x80u) || (sequence_length == 2u && cp < 0x800u) ||
        (sequence_length == 3u && cp < 0x10000u)) {
        return 0;
    }
    *out = cp;
    return 1;
}

static int utf8_to_utf16(const char* value, size_t value_length, UChar* dest, int32_t dest_length, int32_t* out_length)
{
    size_t offset = 0u;
    size_t required = 0u;
    int32_t capacity = dest_length < 0 ? 0 : dest_length;
    while (offset < value_length) {
        uint32_t cp;
        if (!decode_utf8((const unsigned char*)value, value_length, &offset, &cp)) return 0;
        required += cp <= 0xffffu ? 1u : 2u;
    }
    if (required > (size_t)INT32_MAX) return 0;
    if (out_length) *out_length = (int32_t)required;
    if (!dest || required > (size_t)capacity) return required == 0u || !dest ? 1 : 0;
    offset = 0u;
    required = 0u;
    while (offset < value_length) {
        uint32_t cp;
        if (!decode_utf8((const unsigned char*)value, value_length, &offset, &cp)) return 0;
        if (cp <= 0xffffu) dest[required++] = (UChar)cp;
        else {
            cp -= 0x10000u;
            dest[required++] = (UChar)(0xd800u | (cp >> 10));
            dest[required++] = (UChar)(0xdc00u | (cp & 0x3ffu));
        }
    }
    return 1;
}

static int copy_utf8(const char* value, size_t length, UChar* dest, int32_t capacity)
{
    int32_t written = 0;
    if (!utf8_to_utf16(value, length, dest, capacity, &written)) return 0;
    return written;
}

static char* locale_utf8(const UChar* locale)
{
    char* result;
    if (!locale) {
        result = (char*)malloc(5u);
        if (result) memcpy(result, "root", 5u);
        return result;
    }
    return utf16_to_utf8(locale, -1, NULL);
}

static int get_locale_record(const UChar* locale, RinIcuDataLocaleRecord* record)
{
    char* locale_name = locale_utf8(locale);
    rin_icu_client_t* client = product_client();
    int status = RIN_ICU_STATUS_INVALID;
    if (locale_name && client && record) {
        status = rin_icu_locale_info(client, locale_name, record);
    }
    free(locale_name);
    return status == RIN_ICU_STATUS_OK;
}

static size_t record_field_length(const char* field, size_t capacity)
{
    size_t length = 0u;
    if (!field) return 0u;
    while (length < capacity && field[length] != '\0') ++length;
    return length;
}

static int append_pattern_text(char* dest, size_t capacity, size_t* length, const char* text)
{
    size_t text_length = strlen(text);
    if (!dest || !length || *length + text_length >= capacity) return 0;
    memcpy(dest + *length, text, text_length);
    *length += text_length;
    dest[*length] = '\0';
    return 1;
}

static int product_pattern(const char* source, size_t source_capacity,
                           int time_pattern, int month_day,
                           char* dest, size_t capacity)
{
    size_t source_length = record_field_length(source, source_capacity);
    size_t i = 0u;
    size_t length = 0u;
    if (!source || !dest || capacity == 0u) return 0;
    dest[0] = '\0';
    while (i < source_length) {
        const char* replacement = NULL;
        size_t consumed = 1u;
        if (!time_pattern && i + 4u <= source_length && strncmp(source + i, "YYYY", 4u) == 0) {
            replacement = "yyyy";
            consumed = 4u;
        } else if (!time_pattern && i + 2u <= source_length && strncmp(source + i, "MM", 2u) == 0) {
            replacement = "MM";
            consumed = 2u;
        } else if (!time_pattern && i + 2u <= source_length && strncmp(source + i, "DD", 2u) == 0) {
            replacement = "dd";
            consumed = 2u;
        } else if (!time_pattern && source[i] == 'Y') {
            replacement = "yyyy";
        } else if (time_pattern && source[i] == 'a') {
            replacement = "tt";
        }
        if (month_day && !time_pattern && replacement && strcmp(replacement, "yyyy") == 0) {
            size_t skip = consumed;
            if (i > 0u && (source[i - 1u] == '/' || source[i - 1u] == '-' || source[i - 1u] == '.')) {
                if (length > 0u) --length;
            } else if (i + skip < source_length &&
                       (source[i + skip] == '/' || source[i + skip] == '-' || source[i + skip] == '.')) {
                ++skip;
            }
            i += skip;
            if (length > 0u) dest[length] = '\0';
            continue;
        }
        if (replacement) {
            if (!append_pattern_text(dest, capacity, &length, replacement)) return 0;
            i += consumed;
        } else {
            char literal[2] = { source[i], '\0' };
            if (!append_pattern_text(dest, capacity, &length, literal)) return 0;
            ++i;
        }
    }
    return (int)length;
}

static int service_text_call(int (*call)(rin_icu_client_t*, const char*, char*, size_t, size_t*),
                             const char* input, UChar* dest, int32_t capacity)
{
    rin_icu_client_t* client = product_client();
    char buffer[256];
    size_t length = 0u;
    char* dynamic = NULL;
    int status;
    if (!client) return 0;
    status = call(client, input ? input : "", buffer, sizeof(buffer), &length);
    if (status == RIN_ICU_STATUS_NO_SPACE) {
        if (length == SIZE_MAX) return 0;
        dynamic = (char*)malloc(length + 1u);
        if (!dynamic) return 0;
        status = call(client, input ? input : "", dynamic, length + 1u, &length);
    }
    if (status != RIN_ICU_STATUS_OK) {
        free(dynamic);
        return 0;
    }
    status = copy_utf8(dynamic ? dynamic : buffer, length, dest, capacity);
    free(dynamic);
    return status;
}

static int normalize_form(NormalizationForm form)
{
    switch (form) {
        case FormD: return RIN_ICU_NORMALIZE_NFD;
        case FormKC: return RIN_ICU_NORMALIZE_NFKC;
        case FormKD: return RIN_ICU_NORMALIZE_NFKD;
        case FormC: default: return RIN_ICU_NORMALIZE_NFC;
    }
}

static int normalize_utf16(NormalizationForm form, const UChar* source, int32_t source_length, UChar* dest, int32_t dest_length)
{
    size_t source_bytes = 0u;
    size_t output_length = 0u;
    char* input = utf16_to_utf8(source, source_length, &source_bytes);
    char* output;
    rin_icu_client_t* client;
    int status;
    if (!input) return -1;
    client = product_client();
    if (!client) {
        free(input);
        return -1;
    }
    if (source_bytes > (SIZE_MAX - 64u) / 12u) {
        free(input);
        return -1;
    }
    output = (char*)malloc(source_bytes * 12u + 64u);
    if (!output) {
        free(input);
        return -1;
    }
    status = rin_icu_normalize(client, normalize_form(form), input, output, source_bytes * 12u + 64u, &output_length);
    if (status != RIN_ICU_STATUS_OK) {
        free(output);
        free(input);
        return -1;
    }
    status = copy_utf8(output, output_length, dest, dest_length);
    free(output);
    free(input);
    return status;
}

static int case_map(const UChar* source, int32_t source_length, UChar* dest, int32_t dest_length, const char* locale, int to_upper)
{
    size_t source_bytes = 0u;
    size_t output_length = 0u;
    char* input = utf16_to_utf8(source, source_length, &source_bytes);
    char* output;
    rin_icu_client_t* client;
    int status;
    if (!input) return 0;
    client = product_client();
    output = client && source_bytes <= (SIZE_MAX - 64u) / 4u
        ? (char*)malloc(source_bytes * 4u + 64u)
        : NULL;
    if (!output) {
        free(input);
        return 0;
    }
    status = rin_icu_case_map(client, locale ? locale : "root", input, to_upper, output, source_bytes * 4u + 64u, &output_length);
    if (status == RIN_ICU_STATUS_OK) status = copy_utf8(output, output_length, dest, dest_length);
    free(output);
    free(input);
    return status;
}

void GlobalizationNative_ChangeCase(const UChar* source, int32_t source_length, UChar* dest, int32_t dest_length, int32_t to_upper)
{
    (void)case_map(source, source_length, dest, dest_length, "root", to_upper != 0);
}

void GlobalizationNative_ChangeCaseInvariant(const UChar* source, int32_t source_length, UChar* dest, int32_t dest_length, int32_t to_upper)
{
    (void)case_map(source, source_length, dest, dest_length, "root", to_upper != 0);
}

void GlobalizationNative_ChangeCaseTurkish(const UChar* source, int32_t source_length, UChar* dest, int32_t dest_length, int32_t to_upper)
{
    (void)case_map(source, source_length, dest, dest_length, "tr", to_upper != 0);
}

void GlobalizationNative_InitOrdinalCasingPage(int32_t page_number, UChar* target)
{
    uint32_t first_codepoint;
    int i;
    if (!target) return;
    first_codepoint = ((uint32_t)page_number) << 8;
    for (i = 0; i < 256; ++i) {
        target[i] = (UChar)rin_unicode_toupper(first_codepoint + (uint32_t)i);
    }

    /* Ordinal casing deliberately does not use Turkish-I behavior. */
    if (first_codepoint == 0x0100u) {
        target[0x31] = (UChar)0x0131;
        target[0x7f] = (UChar)0x017f;
    }
}

void GlobalizationNative_InitOrdinalLowerCasingPage(int32_t page_number, UChar* target)
{
    uint32_t first_codepoint;
    int i;
    if (!target) return;
    first_codepoint = ((uint32_t)page_number) << 8;
    for (i = 0; i < 256; ++i) {
        target[i] = (UChar)rin_unicode_tolower(first_codepoint + (uint32_t)i);
    }

    /* Keep ordinal ignore-case equivalence symmetric with the upper table. */
    switch (first_codepoint) {
        case 0x0100u:
            target[0x30] = (UChar)0x0130;
            break;
        case 0x0300u:
            target[0xf4] = (UChar)0x03f4;
            break;
        case 0x1e00u:
            target[0x9e] = (UChar)0x1e9e;
            break;
        case 0x2100u:
            target[0x26] = (UChar)0x2126;
            target[0x2a] = (UChar)0x212a;
            target[0x2b] = (UChar)0x212b;
            break;
    }
}

int32_t GlobalizationNative_IsNormalized(NormalizationForm form, const UChar* source, int32_t source_length)
{
    int32_t length = normalize_utf16(form, source, source_length, NULL, 0);
    UChar* normalized;
    int32_t normalized_length;
    int32_t source_units = (int32_t)u16_length(source, source_length);
    if (length < 0) return 0;
    normalized = (UChar*)malloc((size_t)(length + 1) * sizeof(UChar));
    if (!normalized) return 0;
    normalized_length = normalize_utf16(form, source, source_length, normalized, length + 1);
    if (normalized_length < 0 || normalized_length != source_units) {
        free(normalized);
        return 0;
    }
    normalized[normalized_length] = 0u;
    if (memcmp(normalized, source, (size_t)source_units * sizeof(UChar)) != 0) {
        free(normalized);
        return 0;
    }
    free(normalized);
    return 1;
}

int32_t GlobalizationNative_NormalizeString(NormalizationForm form, const UChar* source, int32_t source_length, UChar* dest, int32_t dest_length)
{
    return normalize_utf16(form, source, source_length, dest, dest_length);
}

static int create_sort_handle(const char* locale, SortHandle** out_handle)
{
    rin_icu_client_t* client = product_client();
    rin_icu_collator_options_t options = { 0 };
    SortHandle* result;
    if (!client || !out_handle) return 0;
    options.strength = RIN_ICU_COLLATION_STRENGTH_TERTIARY;
    result = (SortHandle*)calloc(1u, sizeof(SortHandle));
    if (!result) return 0;
    result->client = client;
    if (rin_icu_collator_create(result->client, locale ? locale : "root", &options, &result->handle) != RIN_ICU_STATUS_OK) {
        free(result);
        return 0;
    }
    *out_handle = result;
    return 1;
}

int32_t GlobalizationNative_GetSortHandle(const char* locale, SortHandle** out_handle)
{
    return create_sort_handle(locale, out_handle) ? Success : UnknownError;
}

void GlobalizationNative_CloseSortHandle(SortHandle* handle)
{
    if (!handle) return;
    (void)rin_icu_collator_destroy(handle->client, handle->handle);
    free(handle);
}

int32_t GlobalizationNative_GetSortVersion(SortHandle* handle)
{
    return handle ? (int32_t)RIN_ICU_VERSION : -1;
}

static char* sort_text(const UChar* value, int32_t length, size_t* out_length)
{
    return utf16_to_utf8(value, length, out_length);
}

int32_t GlobalizationNative_CompareString(SortHandle* handle, const UChar* lhs, int32_t lhs_length, const UChar* rhs, int32_t rhs_length, int32_t options)
{
    char* left = sort_text(lhs, lhs_length, NULL);
    char* right = sort_text(rhs, rhs_length, NULL);
    int result = 0;
    (void)options;
    if (!handle || !left || !right || rin_icu_collator_compare(handle->client, handle->handle, left, right, &result) != RIN_ICU_STATUS_OK) result = 0;
    free(left);
    free(right);
    return result;
}

int32_t GlobalizationNative_GetSortKey(SortHandle* handle, const UChar* source, int32_t source_length, uint8_t* dest, int32_t dest_length, int32_t options)
{
    char* input = sort_text(source, source_length, NULL);
    uint8_t buffer[512];
    uint8_t* output = buffer;
    size_t output_length = 0u;
    int status;
    (void)options;
    if (!handle || !input) {
        free(input);
        return 0;
    }
    status = rin_icu_collator_sort_key(handle->client, handle->handle, input, buffer, sizeof(buffer), &output_length);
    if (status == RIN_ICU_STATUS_NO_SPACE) {
        output = (uint8_t*)malloc(output_length + 1u);
        if (output) status = rin_icu_collator_sort_key(handle->client, handle->handle, input, output, output_length + 1u, &output_length);
    }
    if (status != RIN_ICU_STATUS_OK) output_length = 0u;
    if (dest && dest_length > 0 && output_length > 0u) {
        size_t copy_length = output_length < (size_t)dest_length ? output_length : (size_t)dest_length;
        memcpy(dest, output, copy_length);
    }
    free(output == buffer ? NULL : output);
    free(input);
    return (int32_t)output_length;
}

static int compare_slice(SortHandle* handle, const UChar* source, int32_t source_length, int32_t offset, const UChar* target, int32_t target_length)
{
    char* left;
    char* right;
    int result = 0;
    left = sort_text(source + offset, target_length, NULL);
    right = sort_text(target, target_length, NULL);
    if (!left || !right || rin_icu_collator_compare(handle->client, handle->handle, left, right, &result) != RIN_ICU_STATUS_OK) result = 1;
    free(left);
    free(right);
    return result == 0;
}

int32_t GlobalizationNative_IndexOf(SortHandle* handle, const UChar* target, int32_t target_length, const UChar* source, int32_t source_length, int32_t options, int32_t* matched_length)
{
    int32_t i;
    (void)options;
    if (matched_length) *matched_length = 0;
    if (!handle || !target || !source || target_length < 0 || source_length < 0) return -1;
    for (i = 0; i + target_length <= source_length; ++i) {
        if (compare_slice(handle, source, source_length, i, target, target_length)) {
            if (matched_length) *matched_length = target_length;
            return i;
        }
    }
    return -1;
}

int32_t GlobalizationNative_LastIndexOf(SortHandle* handle, const UChar* target, int32_t target_length, const UChar* source, int32_t source_length, int32_t options, int32_t* matched_length)
{
    int32_t i;
    (void)options;
    if (matched_length) *matched_length = 0;
    if (!handle || !target || !source || target_length < 0 || source_length < 0) return -1;
    for (i = source_length - target_length; i >= 0; --i) {
        if (compare_slice(handle, source, source_length, i, target, target_length)) {
            if (matched_length) *matched_length = target_length;
            return i;
        }
    }
    return -1;
}

int32_t GlobalizationNative_StartsWith(SortHandle* handle, const UChar* target, int32_t target_length, const UChar* source, int32_t source_length, int32_t options, int32_t* matched_length)
{
    (void)options;
    if (matched_length) *matched_length = 0;
    if (!handle || target_length < 0 || source_length < target_length) return 0;
    if (!compare_slice(handle, source, source_length, 0, target, target_length)) return 0;
    if (matched_length) *matched_length = target_length;
    return 1;
}

int32_t GlobalizationNative_EndsWith(SortHandle* handle, const UChar* target, int32_t target_length, const UChar* source, int32_t source_length, int32_t options, int32_t* matched_length)
{
    (void)options;
    if (matched_length) *matched_length = 0;
    if (!handle || target_length < 0 || source_length < target_length) return 0;
    if (!compare_slice(handle, source, source_length, source_length - target_length, target, target_length)) return 0;
    if (matched_length) *matched_length = target_length;
    return 1;
}

static int32_t locale_call(const UChar* locale, UChar* value, int32_t value_length, int (*call)(rin_icu_client_t*, const char*, char*, size_t, size_t*))
{
    char* locale_name = locale_utf8(locale);
    int32_t result = service_text_call(call, locale_name, value, value_length);
    free(locale_name);
    return result;
}

int32_t GlobalizationNative_GetLocaleName(const UChar* locale, UChar* value, int32_t value_length)
{
    return locale_call(locale, value, value_length, rin_icu_locale_canonicalize) > 0;
}

int32_t GlobalizationNative_GetDefaultLocaleName(UChar* value, int32_t value_length)
{
    rin_icu_client_t* client = product_client();
    char buffer[128];
    size_t length = 0u;
    if (!client || rin_icu_locale_preferred(client, buffer, sizeof(buffer), &length) != RIN_ICU_STATUS_OK) return 0;
    return copy_utf8(buffer, length, value, value_length) > 0;
}

int32_t GlobalizationNative_IsPredefinedLocale(const UChar* locale)
{
    char* input = locale_utf8(locale);
    char resolved[128];
    size_t length = 0u;
    rin_icu_client_t* client = product_client();
    int result = client && rin_icu_locale_resolve(client, input, resolved, sizeof(resolved), &length) == RIN_ICU_STATUS_OK && strcmp(resolved, "root") != 0;
    free(input);
    return result;
}

static int locale_list_name_valid(const char* name, size_t length)
{
    size_t i;
    if (!name || length == 0u || length >= sizeof(((RinIcuDataLocaleRecord*)0)->locale_id)) return 0;
    for (i = 0u; i < length; ++i) {
        unsigned char ch = (unsigned char)name[i];
        if (!((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
              (ch >= '0' && ch <= '9') || ch == '-' || ch == '_')) {
            return 0;
        }
    }
    return 1;
}

static int locale_list_required(const char* list, size_t length, int32_t* required)
{
    size_t i = 0u;
    size_t count = 0u;
    int32_t total = 0;
    if (!list || !required) return 0;
    while (i < length) {
        size_t start = i;
        size_t name_length;
        while (i < length && list[i] != '\n') ++i;
        name_length = i - start;
        if (!locale_list_name_valid(list + start, name_length) ||
            count >= RIN_ICU_DATA_MAX_LOCALES ||
            name_length + 1u > (size_t)INT32_MAX - (size_t)total) {
            return 0;
        }
        total += (int32_t)(name_length + 1u);
        ++count;
        if (i < length) ++i;
    }
    *required = total;
    return 1;
}

int32_t GlobalizationNative_GetLocales(UChar* value, int32_t value_length)
{
    rin_icu_client_t* client = product_client();
    char* list;
    size_t length = 0u;
    size_t i = 0u;
    int32_t written = 0;
    int32_t required = 0;
    int status;
    if (!client || (value && value_length < 0)) return -1;
    status = rin_icu_locale_available(client, NULL, 0u, &length);
    if (status != RIN_ICU_STATUS_OK || length > RIN_ICU_MAX_INLINE_PAYLOAD || length == SIZE_MAX) return -1;
    list = (char*)malloc(length + 1u);
    if (!list || rin_icu_locale_available(client, list, length + 1u, &length) != RIN_ICU_STATUS_OK) {
        free(list);
        return -1;
    }
    if (!locale_list_required(list, length, &required)) {
        free(list);
        return -1;
    }
    if (value && required > value_length) {
        free(list);
        return -3;
    }
    while (i < length) {
        size_t start = i;
        size_t name_length;
        while (i < length && list[i] != '\n') ++i;
        name_length = i - start;
        if (name_length > 0u) {
            if (value) {
                int32_t at = written;
                value[at++] = (UChar)name_length;
                for (size_t j = 0u; j < name_length; ++j) value[at + (int32_t)j] = (UChar)list[start + j];
                written += (int32_t)name_length + 1;
            }
        }
        if (i < length) ++i;
    }
    free(list);
    return required;
}

int32_t GlobalizationNative_GetLocaleTimeFormat(const UChar* locale, int short_format, UChar* value, int32_t value_length)
{
    RinIcuDataLocaleRecord record;
    char format[128];
    size_t source_length;
    int result;
    if (!get_locale_record(locale, &record)) return 0;
    source_length = record_field_length(record.time_pattern, sizeof(record.time_pattern));
    if (!product_pattern(record.time_pattern, source_length + 1u, 1, 0, format, sizeof(format))) return 0;
    if (short_format) {
        char* seconds = strstr(format, ":ss");
        if (seconds) memmove(seconds, seconds + 3u, strlen(seconds + 3u) + 1u);
    }
    result = copy_utf8(format, strlen(format), value, value_length);
    return result > 0;
}

static int locale_parent_name(rin_icu_client_t* client, const char* locale_name, char* parent, size_t capacity)
{
    char canonical[128];
    char* separator;
    char* underscore;
    size_t length = 0u;
    if (!client || !locale_name || !parent || capacity == 0u ||
        rin_icu_locale_canonicalize(client, locale_name, canonical, sizeof(canonical), &length) != RIN_ICU_STATUS_OK ||
        length >= sizeof(canonical)) {
        return 0;
    }
    canonical[length] = '\0';
    separator = strrchr(canonical, '-');
    underscore = strrchr(canonical, '_');
    if (!separator || (underscore && underscore > separator)) separator = underscore;
    if (!separator) {
        if (capacity < 5u) return 0;
        memcpy(parent, "root", 5u);
        return 1;
    }
    length = (size_t)(separator - canonical);
    if (length == 0u || length >= capacity) return 0;
    memcpy(parent, canonical, length);
    parent[length] = '\0';
    return 1;
}

int32_t GlobalizationNative_GetLocaleInfoString(const UChar* locale, LocaleStringData kind, UChar* value, int32_t value_length, const UChar* ui_locale)
{
    char* locale_name = locale_utf8(locale);
    char* ui_name = locale_utf8(ui_locale);
    RinIcuDataLocaleRecord record;
    char buffer[256];
    char parent[128];
    const char* field = NULL;
    size_t field_capacity = 0u;
    size_t length = 0u;
    int status = RIN_ICU_STATUS_UNSUPPORTED;
    rin_icu_client_t* client = product_client();
    int have_record = get_locale_record(locale, &record);
    if (!locale_name) {
        free(ui_name);
        return 0;
    }
    if (client && have_record && (kind == LocaleString_EnglishDisplayName || kind == LocaleString_NativeDisplayName || kind == LocaleString_LocalizedDisplayName ||
                                  kind == LocaleString_EnglishLanguageName || kind == LocaleString_NativeLanguageName || kind == LocaleString_LocalizedLanguageName ||
                                  kind == LocaleString_EnglishCountryName || kind == LocaleString_NativeCountryName ||
                                  kind == LocaleString_CurrencyEnglishName || kind == LocaleString_CurrencyNativeName)) {
        uint32_t type = RIN_ICU_DISPLAY_NAME_LANGUAGE;
        const char* code = locale_name;
        uint32_t style = RIN_ICU_STYLE_LONG;
        if (kind == LocaleString_EnglishCountryName || kind == LocaleString_NativeCountryName) {
            type = RIN_ICU_DISPLAY_NAME_REGION;
            code = record.region;
        } else if (kind == LocaleString_CurrencyEnglishName || kind == LocaleString_CurrencyNativeName) {
            type = RIN_ICU_DISPLAY_NAME_CURRENCY;
            code = record.currency_code;
        } else if (kind == LocaleString_EnglishLanguageName || kind == LocaleString_NativeLanguageName || kind == LocaleString_LocalizedLanguageName) {
            code = record.language;
        }
        status = rin_icu_display_name(client, ui_name, code, type, style, RIN_ICU_LANGUAGE_DISPLAY_STANDARD, buffer, sizeof(buffer), &length);
    }
    if (status != RIN_ICU_STATUS_OK && have_record) {
        switch (kind) {
            case LocaleString_DecimalSeparator:
            case LocaleString_MonetaryDecimalSeparator: field = record.decimal_sep; field_capacity = sizeof(record.decimal_sep); break;
            case LocaleString_ThousandSeparator:
            case LocaleString_MonetaryThousandSeparator: field = record.group_sep; field_capacity = sizeof(record.group_sep); break;
            case LocaleString_MonetarySymbol: field = record.currency_symbol; field_capacity = sizeof(record.currency_symbol); break;
            case LocaleString_Iso4217MonetarySymbol: field = record.currency_code; field_capacity = sizeof(record.currency_code); break;
            case LocaleString_AMDesignator: field = record.am; field_capacity = sizeof(record.am); break;
            case LocaleString_PMDesignator: field = record.pm; field_capacity = sizeof(record.pm); break;
            case LocaleString_PositiveSign: field = record.plus_sign; field_capacity = sizeof(record.plus_sign); break;
            case LocaleString_NegativeSign: field = record.minus_sign; field_capacity = sizeof(record.minus_sign); break;
            case LocaleString_PercentSymbol: field = record.percent_sign; field_capacity = sizeof(record.percent_sign); break;
            case LocaleString_Iso639LanguageTwoLetterName: field = record.language; field_capacity = sizeof(record.language); break;
            case LocaleString_Iso3166CountryName: field = record.region; field_capacity = sizeof(record.region); break;
            case LocaleString_ParentName:
                if (locale_parent_name(client, locale_name, parent, sizeof(parent))) {
                    field = parent;
                    field_capacity = sizeof(parent);
                }
                break;
            case LocaleString_Digits: field = "0123456789"; field_capacity = 11u; break;
            default: break;
        }
        if (field) {
            length = record_field_length(field, field_capacity);
            if (length < sizeof(buffer)) memcpy(buffer, field, length);
            status = length < sizeof(buffer) ? RIN_ICU_STATUS_OK : RIN_ICU_STATUS_NO_SPACE;
        }
    }
    free(locale_name);
    free(ui_name);
    if (status != RIN_ICU_STATUS_OK) return 0;
    return copy_utf8(buffer, length, value, value_length) > 0;
}

int32_t GlobalizationNative_GetLocaleInfoInt(const UChar* locale, LocaleNumberData kind, int32_t* value)
{
    RinIcuDataLocaleRecord record;
    int have_record = get_locale_record(locale, &record);
    if (!value) return 0;
    if (!have_record) return 0;
    switch (kind) {
        case LocaleNumber_MeasurementSystem:
            *value = (strcmp(record.region, "US") == 0 || strcmp(record.region, "LR") == 0 || strcmp(record.region, "MM") == 0) ? 1 : 0;
            break;
        case LocaleNumber_FirstDayofWeek: *value = (strcmp(record.region, "US") == 0 || strcmp(record.region, "CA") == 0) ? 0 : 1; break;
        case LocaleNumber_FractionalDigitsCount:
        case LocaleNumber_MonetaryFractionalDigitsCount: *value = (int32_t)record.currency_digits; break;
        case LocaleNumber_Monetary: *value = record.currency_code[0] != '\0'; break;
        default: return 0;
    }
    return 1;
}

int32_t GlobalizationNative_GetLocaleInfoGroupingSizes(const UChar* locale, LocaleNumberData kind, int32_t* primary, int32_t* secondary)
{
    RinIcuDataLocaleRecord record;
    if (!primary || !secondary) return 0;
    if (kind != LocaleNumber_Digit && kind != LocaleNumber_Monetary) return 0;
    if (!get_locale_record(locale, &record)) return 0;
    *primary = record.group_sep[0] == '\0' ? 0 : 3;
    *secondary = *primary;
    return 1;
}

int32_t GlobalizationNative_GetCalendars(const UChar* locale, CalendarId* calendars, int32_t capacity)
{
    RinIcuDataLocaleRecord record;
    if (!calendars || capacity <= 0 || !get_locale_record(locale, &record)) return 0;
    calendars[0] = 1;
    if (strcmp(record.language, "ja") == 0 && capacity > 1) {
        calendars[1] = 3;
        return 2;
    }
    return 1;
}

ResultCode GlobalizationNative_GetCalendarInfo(const UChar* locale, CalendarId calendar, CalendarDataType kind, UChar* value, int32_t capacity)
{
    RinIcuDataLocaleRecord record;
    char pattern[128];
    const char* text = calendar == 3 ? "japanese" : "gregorian";
    if ((calendar != 1 && calendar != 3) || capacity < 0 || !get_locale_record(locale, &record)) return UnknownError;
    switch (kind) {
        case CalendarData_NativeName:
            break;
        case CalendarData_MonthDay:
        case CalendarData_ShortDates:
        case CalendarData_LongDates:
            if (!product_pattern(record.date_pattern, sizeof(record.date_pattern), 0, kind == CalendarData_MonthDay, pattern, sizeof(pattern))) return UnknownError;
            text = pattern;
            break;
        default:
            return UnknownError;
    }
    return copy_utf8(text, strlen(text), value, capacity) > 0 ? Success : InsufficientBuffer;
}

int32_t GlobalizationNative_EnumCalendarInfo(EnumCalendarInfoCallback callback, const UChar* locale, CalendarId calendar, CalendarDataType kind, const void* context)
{
    static const UChar gregorian[] = { 'g','r','e','g','o','r','i','a','n',0 };
    static const UChar japanese[] = { 'j','a','p','a','n','e','s','e',0 };
    RinIcuDataLocaleRecord record;
    UChar pattern[128];
    int32_t pattern_length;
    if (!callback || (calendar != 1 && calendar != 3) || !get_locale_record(locale, &record)) return 0;
    if (kind == CalendarData_NativeName) {
        callback(calendar == 3 ? japanese : gregorian, context);
        return 1;
    }
    if (calendar == 3 && (kind == CalendarData_EraNames || kind == CalendarData_AbbrevEraNames)) {
        size_t index;
        for (index = 0u; index < sizeof(g_japanese_era_names) / sizeof(g_japanese_era_names[0]); ++index) {
            UChar era_name[32];
            const char* name = kind == CalendarData_EraNames
                ? g_japanese_era_names[index]
                : g_japanese_era_abbreviations[index];
            int32_t length = copy_utf8(name, strlen(name), era_name, (int32_t)(sizeof(era_name) / sizeof(era_name[0])));
            if (length <= 0) return 0;
            era_name[length] = 0;
            callback(era_name, context);
        }
        return (int32_t)(sizeof(g_japanese_era_names) / sizeof(g_japanese_era_names[0]));
    }
    if (kind != CalendarData_ShortDates && kind != CalendarData_LongDates) return 0;
    {
        char product_format[128];
        if (!product_pattern(record.date_pattern, sizeof(record.date_pattern), 0, 0, product_format, sizeof(product_format))) return 0;
        pattern_length = copy_utf8(product_format, strlen(product_format), pattern, (int32_t)(sizeof(pattern) / sizeof(pattern[0])));
    }
    if (pattern_length <= 0) return 0;
    pattern[pattern_length] = 0;
    callback(pattern, context);
    return 1;
}

int32_t GlobalizationNative_GetLatestJapaneseEra(void)
{
    return (int32_t)(sizeof(g_japanese_eras) / sizeof(g_japanese_eras[0])) - 1;
}

int32_t GlobalizationNative_GetJapaneseEraStartDate(int32_t era, int32_t* year, int32_t* month, int32_t* day)
{
    size_t era_count = sizeof(g_japanese_eras) / sizeof(g_japanese_eras[0]);
    if (!year || !month || !day) return 0;
    *year = -1;
    *month = -1;
    *day = -1;
    if (era < 0 || (size_t)era >= era_count) return 0;
    *year = g_japanese_eras[era].start_year;
    *month = g_japanese_eras[era].start_month;
    *day = g_japanese_eras[era].start_day;
    return 1;
}

int32_t GlobalizationNative_LoadICU(void)
{
    return product_client() != NULL;
}

void GlobalizationNative_InitICUFunctions(void* icuuc, void* icuin, const char* version, const char* suffix)
{
    (void)icuuc;
    (void)icuin;
    (void)version;
    (void)suffix;
}

int32_t GlobalizationNative_GetICUVersion(void)
{
    return (int32_t)RIN_ICU_VERSION;
}

int32_t GlobalizationNative_LoadICUData(const char* path)
{
    (void)path;
    return GlobalizationNative_LoadICU();
}

static int copy_ascii_id(const UChar* source, int32_t source_length, UChar* dest, int32_t dest_length)
{
    int32_t i;
    if (!source || source_length < 0) return 0;
    for (i = 0; i < source_length; ++i) if (source[i] > 0x7fu) return 0;
    if (dest && dest_length < source_length + 1) return 0;
    if (dest) {
        for (i = 0; i < source_length; ++i) dest[i] = source[i];
        dest[source_length] = 0;
    }
    return source_length;
}

static int u16_ascii_equal(const UChar* value, size_t length, const char* ascii)
{
    size_t i;
    size_t ascii_length = strlen(ascii);
    if (length != ascii_length) return 0;
    for (i = 0u; i < length; ++i) {
        if (value[i] != (UChar)(unsigned char)ascii[i]) return 0;
    }
    return 1;
}

static int ascii_region_equal(const char* value, const char* expected)
{
    size_t i;
    if (!value || !expected || strlen(value) != strlen(expected)) return 0;
    for (i = 0u; value[i] != '\0'; ++i) {
        char left = value[i];
        char right = expected[i];
        if (left >= 'a' && left <= 'z') left = (char)(left - 'a' + 'A');
        if (right >= 'a' && right <= 'z') right = (char)(right - 'a' + 'A');
        if (left != right) return 0;
    }
    return 1;
}

static int copy_ascii_text(const char* source, UChar* dest, int32_t dest_length)
{
    size_t length;
    size_t i;
    if (!source) return 0;
    length = strlen(source);
    if (length > (size_t)INT32_MAX ||
        (dest && (dest_length < 0 || (size_t)dest_length < length + 1u))) return 0;
    if (dest) {
        for (i = 0u; i < length; ++i) dest[i] = (UChar)(unsigned char)source[i];
        dest[length] = 0;
    }
    return (int)length;
}

typedef struct RinTimeZoneIdMapping
{
    const char* windows_id;
    const char* iana_id;
    const char* region;
} RinTimeZoneIdMapping;

static const RinTimeZoneIdMapping g_time_zone_id_mappings[] = {
    { "Eastern Standard Time", "America/New_York", "US" },
    { "Central Standard Time", "America/Chicago", "US" },
    { "Mountain Standard Time", "America/Denver", "US" },
    { "Pacific Standard Time", "America/Los_Angeles", "US" },
    { "GMT Standard Time", "Europe/London", "GB" },
    { "W. Europe Standard Time", "Europe/Berlin", "DE" },
    { "Tokyo Standard Time", "Asia/Tokyo", "JP" },
    { "Korea Standard Time", "Asia/Seoul", "KR" },
    { "China Standard Time", "Asia/Shanghai", "CN" },
    { "AUS Eastern Standard Time", "Australia/Sydney", "AU" },
    { "New Zealand Standard Time", "Pacific/Auckland", "NZ" },
    { "UTC", "Etc/UTC", "001" },
};

enum {
    RIN_IDNA_MAX_NAME = 4096,
    RIN_IDNA_MAX_LABEL = 63,
    RIN_IDNA_BASE = 36,
    RIN_IDNA_TMIN = 1,
    RIN_IDNA_TMAX = 26,
    RIN_IDNA_SKEW = 38,
    RIN_IDNA_DAMP = 700,
    RIN_IDNA_INITIAL_BIAS = 72,
    RIN_IDNA_INITIAL_N = 128
};

static int idna_append(char* dest, size_t capacity, size_t* length,
                       const char* source, size_t source_length)
{
    if (!dest || !length || !source || *length >= capacity ||
        source_length >= capacity - *length) return 0;
    memcpy(dest + *length, source, source_length);
    *length += source_length;
    dest[*length] = '\0';
    return 1;
}

static int idna_ascii_digit(char value)
{
    if (value >= 'a' && value <= 'z') return value - 'a';
    if (value >= 'A' && value <= 'Z') return value - 'A';
    if (value >= '0' && value <= '9') return value - '0' + 26;
    return -1;
}

static char idna_encode_digit(uint32_t value)
{
    return value < 26u ? (char)('a' + value) : (char)('0' + value - 26u);
}

static uint32_t idna_adapt(uint64_t delta, uint64_t points, int first)
{
    uint64_t k = 0u;
    delta = first ? delta / RIN_IDNA_DAMP : delta / 2u;
    delta += delta / points;
    while (delta > ((RIN_IDNA_BASE - RIN_IDNA_TMIN) * RIN_IDNA_TMAX) / 2u) {
        delta /= RIN_IDNA_BASE - RIN_IDNA_TMIN;
        k += RIN_IDNA_BASE;
    }
    return (uint32_t)(k + ((RIN_IDNA_BASE - RIN_IDNA_TMIN + 1u) * delta) /
                      (delta + RIN_IDNA_SKEW));
}

static int idna_codepoint_allowed(uint32_t codepoint)
{
    /* LibUnicode does not expose the complete IDNA derived-property table.
     * Accept the product's scalar alphanumeric and combining set, and fail
     * closed for join controls, bidi controls, punctuation, and unassigned
     * values instead of claiming a broader UTS-46 profile. */
    if (codepoint <= 0x7fu) {
        return (codepoint >= 'a' && codepoint <= 'z') ||
               (codepoint >= 'A' && codepoint <= 'Z') ||
               (codepoint >= '0' && codepoint <= '9') || codepoint == '-';
    }
    return rin_unicode_isalnum(codepoint) ||
           rin_unicode_is_combining(codepoint);
}

static int idna_ascii_label_valid(const char* label, size_t length)
{
    size_t index;
    if (!label || length == 0u || length > RIN_IDNA_MAX_LABEL ||
        label[0] == '-' || label[length - 1u] == '-') return 0;
    for (index = 0u; index < length; ++index) {
        char value = label[index];
        if (!((value >= 'a' && value <= 'z') ||
              (value >= 'A' && value <= 'Z') ||
              (value >= '0' && value <= '9') || value == '-')) return 0;
    }
    return 1;
}

static int idna_punycode_encode(uint32_t const* input, size_t input_length,
                                char* output, size_t output_capacity,
                                size_t* output_length)
{
    size_t basic = 0u;
    size_t handled;
    size_t index;
    uint32_t n = RIN_IDNA_INITIAL_N;
    uint32_t bias = RIN_IDNA_INITIAL_BIAS;
    uint64_t delta = 0u;
    size_t length = 0u;
    if (!input || !output || !output_length || input_length == 0u) return 0;
    if (!idna_append(output, output_capacity, &length, "xn--", 4u)) return 0;
    for (index = 0u; index < input_length; ++index) {
        if (input[index] < 0x80u) {
            char basic_char = (char)rin_unicode_tolower(input[index]);
            if (!idna_append(output, output_capacity, &length, &basic_char, 1u)) return 0;
            ++basic;
        }
    }
    handled = basic;
    if (basic != 0u && handled != input_length) {
        if (!idna_append(output, output_capacity, &length, "-", 1u)) return 0;
    }
    while (handled < input_length) {
        uint32_t minimum = UINT32_MAX;
        for (index = 0u; index < input_length; ++index) {
            if (input[index] >= n && input[index] < minimum) minimum = input[index];
        }
        if (minimum == UINT32_MAX || minimum < n ||
            (uint64_t)(minimum - n) > (UINT64_MAX - delta) / (handled + 1u)) return 0;
        delta += (uint64_t)(minimum - n) * (handled + 1u);
        n = minimum;
        for (index = 0u; index < input_length; ++index) {
            uint32_t value = input[index];
            if (value < n) {
                if (delta == UINT64_MAX) return 0;
                ++delta;
            }
            if (value == n) {
                uint64_t q = delta;
                uint32_t k = RIN_IDNA_BASE;
                for (;;) {
                    uint32_t threshold = k <= bias + RIN_IDNA_TMIN
                        ? RIN_IDNA_TMIN
                        : k >= bias + RIN_IDNA_TMAX
                            ? RIN_IDNA_TMAX
                            : k - bias;
                    uint32_t digit;
                    if (q < threshold) break;
                    digit = threshold + (uint32_t)((q - threshold) % (RIN_IDNA_BASE - threshold));
                    {
                        char encoded = idna_encode_digit(digit);
                        if (!idna_append(output, output_capacity, &length, &encoded, 1u)) return 0;
                    }
                    q = (q - threshold) / (RIN_IDNA_BASE - threshold);
                    if (k > UINT32_MAX - RIN_IDNA_BASE) return 0;
                    k += RIN_IDNA_BASE;
                }
                {
                    char encoded = idna_encode_digit((uint32_t)q);
                    if (!idna_append(output, output_capacity, &length, &encoded, 1u)) return 0;
                }
                bias = idna_adapt(delta, handled + 1u, handled == basic);
                delta = 0u;
                ++handled;
            }
        }
        if (delta == UINT64_MAX || n == UINT32_MAX) return 0;
        ++delta;
        ++n;
    }
    if (length == 4u || length > RIN_IDNA_MAX_LABEL) return 0;
    *output_length = length;
    return 1;
}

static int idna_punycode_decode(const char* input, size_t input_length,
                                uint32_t* output, size_t output_capacity,
                                size_t* output_length)
{
    size_t delimiter = SIZE_MAX;
    size_t index;
    size_t out = 0u;
    uint32_t n = RIN_IDNA_INITIAL_N;
    uint32_t bias = RIN_IDNA_INITIAL_BIAS;
    uint64_t i = 0u;
    if (!input || !output || !output_length || input_length == 0u) return 0;
    for (index = 0u; index < input_length; ++index) {
        if (input[index] == '-') delimiter = index;
    }
    if (delimiter == SIZE_MAX) delimiter = 0u;
    for (index = 0u; index < delimiter; ++index) {
        char value = input[index];
        if ((unsigned char)value >= 0x80u ||
            !((value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z') ||
              (value >= '0' && value <= '9') || value == '-')) return 0;
        if (out >= output_capacity) return 0;
        output[out++] = (uint32_t)(unsigned char)rin_unicode_tolower((uint32_t)(unsigned char)value);
    }
    index = delimiter == 0u ? 0u : delimiter + 1u;
    while (index < input_length) {
        uint64_t old_i = i;
        uint64_t delta_i;
        uint64_t weight = 1u;
        uint32_t k = RIN_IDNA_BASE;
        for (;;) {
            uint32_t threshold;
            int value;
            if (index >= input_length) return 0;
            value = idna_ascii_digit(input[index++]);
            if (value < 0 || (uint64_t)value > (UINT64_MAX - i) / weight) return 0;
            i += (uint64_t)value * weight;
            threshold = k <= bias + RIN_IDNA_TMIN
                ? RIN_IDNA_TMIN
                : k >= bias + RIN_IDNA_TMAX
                    ? RIN_IDNA_TMAX
                    : k - bias;
            if ((uint32_t)value < threshold) break;
            if (weight > UINT64_MAX / (RIN_IDNA_BASE - threshold)) return 0;
            weight *= RIN_IDNA_BASE - threshold;
            if (k > UINT32_MAX - RIN_IDNA_BASE) return 0;
            k += RIN_IDNA_BASE;
        }
        if (out >= output_capacity || i / (out + 1u) > UINT32_MAX - n) return 0;
        delta_i = i - old_i;
        n += (uint32_t)(i / (out + 1u));
        i %= out + 1u;
        memmove(output + i + 1u, output + i, (out - (size_t)i) * sizeof(output[0]));
        output[i] = n;
        ++out;
        bias = idna_adapt(delta_i, out, old_i == 0u);
        i++;
        if (!idna_codepoint_allowed(n)) return 0;
    }
    *output_length = out;
    return out != 0u;
}

static int idna_label_is_ace(const char* label, size_t length)
{
    size_t index;
    if (length < 4u) return 0;
    if (!(label[0] == 'x' || label[0] == 'X') ||
        !(label[1] == 'n' || label[1] == 'N') || label[2] != '-' || label[3] != '-') return 0;
    for (index = 4u; index < length; ++index) {
        char value = label[index];
        if (idna_ascii_digit(value) < 0 && value != '-') return 0;
    }
    return 1;
}

static char* idna_normalize_casefold(const char* source, size_t source_length)
{
    char* input;
    char* normalized;
    char* folded;
    size_t normalized_length;
    size_t folded_capacity;
    size_t folded_length = 0u;
    size_t offset = 0u;
    if (!source || source_length > RIN_IDNA_MAX_NAME - 1u) return NULL;
    input = (char*)malloc(source_length + 1u);
    if (!input) return NULL;
    memcpy(input, source, source_length);
    input[source_length] = '\0';
    normalized_length = rin_unicode_normalize_utf8(NULL, 0u, input, RIN_UNICODE_NORMALIZE_NFKC);
    if (normalized_length == SIZE_MAX || normalized_length > RIN_IDNA_MAX_NAME - 1u) {
        free(input);
        return NULL;
    }
    normalized = (char*)malloc(normalized_length + 1u);
    if (!normalized || rin_unicode_normalize_utf8(normalized, normalized_length + 1u,
                                                   input, RIN_UNICODE_NORMALIZE_NFKC) == SIZE_MAX) {
        free(normalized);
        free(input);
        return NULL;
    }
    if (normalized_length > (RIN_IDNA_MAX_NAME - 1u) / 2u) {
        free(normalized);
        free(input);
        return NULL;
    }
    folded_capacity = normalized_length * 2u + 1u;
    folded = (char*)malloc(folded_capacity);
    if (!folded) {
        free(normalized);
        free(input);
        return NULL;
    }
    while (offset < normalized_length) {
        uint32_t codepoint;
        size_t consumed = 0u;
        uint32_t mapped[3];
        size_t mapped_length;
        size_t mapped_index;
        if (rin_unicode_decode_utf8(normalized + offset, normalized_length - offset,
                                    &codepoint, &consumed) != RIN_UNICODE_OK || consumed == 0u) {
            free(folded);
            free(normalized);
            free(input);
            return NULL;
        }
        mapped_length = rin_unicode_casefold_full(codepoint, mapped);
        for (mapped_index = 0u; mapped_index < mapped_length; ++mapped_index) {
            if (!append_utf8(folded, folded_capacity, &folded_length, mapped[mapped_index])) {
                free(folded);
                free(normalized);
                free(input);
                return NULL;
            }
        }
        offset += consumed;
    }
    free(normalized);
    free(input);
    return folded;
}

static int idna_to_ascii_utf8(const char* source, size_t source_length,
                              char* output, size_t output_capacity,
                              size_t* output_length)
{
    char* normalized = idna_normalize_casefold(source, source_length);
    size_t source_offset = 0u;
    size_t output_offset = 0u;
    int trailing_dot = 0;
    if (!normalized || !output || !output_length) {
        free(normalized);
        return 0;
    }
    while (source_offset <= strlen(normalized)) {
        size_t label_start = source_offset;
        size_t label_end = label_start;
        uint32_t* codepoints;
        size_t codepoint_count = 0u;
        size_t offset = label_start;
        int all_ascii = 1;
        char ascii_label[RIN_IDNA_MAX_LABEL + 1u];
        char punycode[RIN_IDNA_MAX_LABEL + 1u];
        size_t encoded_length = 0u;
        while (normalized[label_end] != '\0' && normalized[label_end] != '.') ++label_end;
        if (label_end == label_start) {
            trailing_dot = normalized[label_end] == '.' && normalized[label_end + 1u] == '\0';
            if (!trailing_dot) {
                free(normalized);
                return 0;
            }
            if (output_offset + 1u >= output_capacity) {
                free(normalized);
                return 0;
            }
            output[output_offset++] = '.';
            output[output_offset] = '\0';
            break;
        }
        codepoints = (uint32_t*)malloc((label_end - label_start + 1u) * sizeof(uint32_t));
        if (!codepoints) {
            free(normalized);
            return 0;
        }
        while (offset < label_end) {
            uint32_t codepoint;
            size_t consumed = 0u;
            if (rin_unicode_decode_utf8(normalized + offset, label_end - offset,
                                        &codepoint, &consumed) != RIN_UNICODE_OK || consumed == 0u ||
                codepoint_count >= label_end - label_start + 1u) {
                free(codepoints);
                free(normalized);
                return 0;
            }
            codepoints[codepoint_count++] = codepoint;
            if (codepoint >= 0x80u) all_ascii = 0;
            offset += consumed;
        }
        if (all_ascii) {
            size_t i;
            if (codepoint_count > RIN_IDNA_MAX_LABEL) {
                free(codepoints);
                free(normalized);
                return 0;
            }
            for (i = 0u; i < codepoint_count; ++i) ascii_label[i] = (char)codepoints[i];
            ascii_label[codepoint_count] = '\0';
            if (!idna_ascii_label_valid(ascii_label, codepoint_count)) {
                free(codepoints);
                free(normalized);
                return 0;
            }
            if (!idna_append(output, output_capacity, &output_offset, ascii_label, codepoint_count)) {
                free(codepoints);
                free(normalized);
                return 0;
            }
        } else {
            size_t i;
            for (i = 0u; i < codepoint_count; ++i) {
                if (!idna_codepoint_allowed(codepoints[i])) {
                    free(codepoints);
                    free(normalized);
                    return 0;
                }
            }
            if (!idna_punycode_encode(codepoints, codepoint_count, punycode,
                                      sizeof(punycode), &encoded_length) ||
                !idna_append(output, output_capacity, &output_offset, punycode, encoded_length)) {
                free(codepoints);
                free(normalized);
                return 0;
            }
        }
        free(codepoints);
        if (normalized[label_end] == '\0') break;
        source_offset = label_end + 1u;
        if (normalized[source_offset] == '\0') {
            if (output_offset + 1u >= output_capacity) {
                free(normalized);
                return 0;
            }
            output[output_offset++] = '.';
            output[output_offset] = '\0';
            break;
        }
        if (!idna_append(output, output_capacity, &output_offset, ".", 1u)) {
            free(normalized);
            return 0;
        }
    }
    free(normalized);
    if (trailing_dot) {
        /* The branch above already emitted the root label separator. */
    }
    if (output_offset == 0u || output_offset > 255u) return 0;
    *output_length = output_offset;
    return 1;
}

static int idna_to_unicode_utf8(const char* source, size_t source_length,
                                char* output, size_t output_capacity,
                                size_t* output_length)
{
    size_t source_offset = 0u;
    size_t output_offset = 0u;
    if (!source || !output || !output_length || source_length > RIN_IDNA_MAX_NAME - 1u) return 0;
    while (source_offset <= source_length) {
        size_t label_start = source_offset;
        size_t label_end = label_start;
        if (label_start == source_length) {
            if (label_start == 0u || source[label_start - 1u] != '.') return 0;
            break;
        }
        while (label_end < source_length && source[label_end] != '.') ++label_end;
        if (label_end == label_start) return 0;
        if (idna_label_is_ace(source + label_start, label_end - label_start)) {
            uint32_t decoded[RIN_IDNA_MAX_LABEL + 1u];
            size_t decoded_length = 0u;
            size_t i;
            if (!idna_punycode_decode(source + label_start + 4u,
                                      label_end - label_start - 4u,
                                      decoded, sizeof(decoded) / sizeof(decoded[0]),
                                      &decoded_length)) return 0;
            for (i = 0u; i < decoded_length; ++i) {
                if (!idna_codepoint_allowed(decoded[i]) ||
                    !append_utf8(output, output_capacity, &output_offset, decoded[i])) return 0;
            }
        } else {
            size_t i;
            if (!idna_ascii_label_valid(source + label_start, label_end - label_start)) return 0;
            for (i = label_start; i < label_end; ++i) {
                char lower = (char)rin_unicode_tolower((uint32_t)(unsigned char)source[i]);
                if (!idna_append(output, output_capacity, &output_offset, &lower, 1u)) return 0;
            }
        }
        if (label_end == source_length) break;
        if (!idna_append(output, output_capacity, &output_offset, ".", 1u)) return 0;
        source_offset = label_end + 1u;
        if (source_offset == source_length) break;
    }
    if (output_offset == 0u) return 0;
    *output_length = output_offset;
    return 1;
}

static int32_t idna_copy_result(const char* value, size_t length,
                                UChar* dest, int32_t dest_length)
{
    int32_t required = 0;
    if (!value || !utf8_to_utf16(value, length, NULL, 0, &required)) return 0;
    if (!dest || dest_length < required) return required;
    if (!utf8_to_utf16(value, length, dest, dest_length, &required)) return 0;
    return required;
}

int32_t GlobalizationNative_ToAscii(uint32_t flags, const UChar* source, int32_t source_length, UChar* dest, int32_t dest_length)
{
    char* input;
    char output[RIN_IDNA_MAX_NAME];
    size_t input_length;
    size_t output_length = 0u;
    (void)flags;
    input = utf16_to_utf8(source, source_length, &input_length);
    if (!input || !idna_to_ascii_utf8(input, input_length, output, sizeof(output), &output_length)) {
        free(input);
        return 0;
    }
    free(input);
    return idna_copy_result(output, output_length, dest, dest_length);
}

int32_t GlobalizationNative_ToUnicode(uint32_t flags, const UChar* source, int32_t source_length, UChar* dest, int32_t dest_length)
{
    char* input;
    char output[RIN_IDNA_MAX_NAME];
    size_t input_length;
    size_t output_length = 0u;
    (void)flags;
    input = utf16_to_utf8(source, source_length, &input_length);
    if (!input || !idna_to_unicode_utf8(input, input_length, output, sizeof(output), &output_length)) {
        free(input);
        return 0;
    }
    free(input);
    return idna_copy_result(output, output_length, dest, dest_length);
}

static int timezone_text_call(const UChar* source, UChar* dest, int32_t dest_length, int (*call)(rin_icu_client_t*, const char*, char*, size_t, size_t*))
{
    return locale_call(source, dest, dest_length, call);
}

static uint32_t timezone_display_service_type(TimeZoneDisplayNameType type)
{
    switch (type) {
        case TimeZoneDisplayName_Generic: return RIN_ICU_DISPLAY_NAME_TIME_ZONE;
        case TimeZoneDisplayName_Standard: return 9u;
        case TimeZoneDisplayName_DaylightSavings: return 10u;
        case TimeZoneDisplayName_GenericLocation: return 11u;
        case TimeZoneDisplayName_ExemplarCity: return 12u;
        case TimeZoneDisplayName_TimeZoneName: return 13u;
        default: return 0u;
    }
}

static int timezone_display_name_call(const UChar* locale, const UChar* time_zone,
                                      TimeZoneDisplayNameType type, UChar* dest,
                                      int32_t dest_length)
{
    char* locale_name = locale_utf8(locale);
    char* time_zone_name = utf16_to_utf8(time_zone, -1, NULL);
    rin_icu_client_t* client = product_client();
    char buffer[256];
    char* dynamic = NULL;
    size_t length = 0u;
    uint32_t service_type = timezone_display_service_type(type);
    uint32_t style = type == TimeZoneDisplayName_TimeZoneName ?
        RIN_ICU_STYLE_SHORT : RIN_ICU_STYLE_LONG;
    int status;
    if (!locale_name || !time_zone_name || !client || service_type == 0u) {
        free(locale_name);
        free(time_zone_name);
        return 0;
    }
    status = rin_icu_display_name(client, locale_name, time_zone_name,
                                  service_type, style,
                                  RIN_ICU_LANGUAGE_DISPLAY_STANDARD,
                                  buffer, sizeof(buffer), &length);
    if (status == RIN_ICU_STATUS_NO_SPACE) {
        if (length == SIZE_MAX) {
            free(locale_name);
            free(time_zone_name);
            return 0;
        }
        dynamic = (char*)malloc(length + 1u);
        if (!dynamic) {
            free(locale_name);
            free(time_zone_name);
            return 0;
        }
        status = rin_icu_display_name(client, locale_name, time_zone_name,
                                      service_type, style,
                                      RIN_ICU_LANGUAGE_DISPLAY_STANDARD,
                                      dynamic, length + 1u, &length);
    }
    free(locale_name);
    free(time_zone_name);
    if (status != RIN_ICU_STATUS_OK || length == 0u) {
        free(dynamic);
        return 0;
    }
    status = copy_utf8(dynamic ? dynamic : buffer, length, dest, dest_length);
    free(dynamic);
    return status;
}

int32_t GlobalizationNative_WindowsIdToIanaId(const UChar* windows_id, const char* region, UChar* iana_id, int32_t iana_length)
{
    const RinTimeZoneIdMapping* mapping = NULL;
    size_t length;
    size_t i;
    if (!windows_id) return 0;
    length = u16_length(windows_id, -1);
    for (i = 0u; i < sizeof(g_time_zone_id_mappings) / sizeof(g_time_zone_id_mappings[0]); ++i) {
        RinTimeZoneIdMapping const* candidate = &g_time_zone_id_mappings[i];
        if (u16_ascii_equal(windows_id, length, candidate->windows_id) &&
            (!region || region[0] == '\0' ||
             strcmp(candidate->region, "001") == 0 ||
             ascii_region_equal(region, candidate->region))) {
            mapping = candidate;
            break;
        }
    }
    return mapping ? copy_ascii_text(mapping->iana_id, iana_id, iana_length) : 0;
}

int32_t GlobalizationNative_IanaIdToWindowsId(const UChar* iana_id, UChar* windows_id, int32_t windows_length)
{
    const RinTimeZoneIdMapping* mapping = NULL;
    size_t length;
    size_t i;
    if (!iana_id) return 0;
    length = u16_length(iana_id, -1);
    for (i = 0u; i < sizeof(g_time_zone_id_mappings) / sizeof(g_time_zone_id_mappings[0]); ++i) {
        RinTimeZoneIdMapping const* candidate = &g_time_zone_id_mappings[i];
        if (u16_ascii_equal(iana_id, length, candidate->iana_id)) {
            mapping = candidate;
            break;
        }
    }
    return mapping ? copy_ascii_text(mapping->windows_id, windows_id, windows_length) : 0;
}

ResultCode GlobalizationNative_GetTimeZoneDisplayName(const UChar* locale, const UChar* time_zone, TimeZoneDisplayNameType type, UChar* result, int32_t result_length)
{
    int32_t required = timezone_display_name_call(locale, time_zone, type, NULL, 0);
    if (required <= 0) return UnknownError;
    if (result && result_length < required) return InsufficientBuffer;
    if (result && timezone_display_name_call(locale, time_zone, type, result, result_length) <= 0) return UnknownError;
    return Success;
}
