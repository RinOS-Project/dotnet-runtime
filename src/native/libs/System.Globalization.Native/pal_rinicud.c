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
#include <stdlib.h>
#include <string.h>

#include "../../../../../rinicu/rin_icu.h"

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

static rin_icu_client_t g_client = { -1, 1u, 0u };

static rin_icu_client_t* product_client(void)
{
    if (g_client.fd < 0 && rin_icu_client_open(&g_client) != RIN_ICU_STATUS_OK) {
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
    size_t length = u16_length(value, value_length);
    size_t capacity = length * 4u + 1u;
    size_t at = 0u;
    char* result;
    size_t i;
    if (!value) return NULL;
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
    result = utf16_to_utf8(locale, -1, NULL);
    if (!result) {
        result = (char*)malloc(5u);
        if (result) memcpy(result, "root", 5u);
    }
    return result;
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
    output = client ? (char*)malloc(source_bytes * 4u + 64u) : NULL;
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
    (void)page_number;
    if (target) memset(target, 0, 256u * sizeof(UChar));
}

void GlobalizationNative_InitOrdinalLowerCasingPage(int32_t page_number, UChar* target)
{
    (void)page_number;
    if (target) memset(target, 0, 256u * sizeof(UChar));
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

int32_t GlobalizationNative_GetLocales(UChar* value, int32_t value_length)
{
    rin_icu_client_t* client = product_client();
    char* list;
    size_t length = 0u;
    size_t i = 0u;
    int32_t required = 0;
    int status;
    if (!client) return -1;
    status = rin_icu_locale_available(client, NULL, 0u, &length);
    if (status != RIN_ICU_STATUS_OK) return -1;
    list = (char*)malloc(length + 1u);
    if (!list || rin_icu_locale_available(client, list, length + 1u, &length) != RIN_ICU_STATUS_OK) {
        free(list);
        return -1;
    }
    while (i < length) {
        size_t start = i;
        size_t name_length;
        while (i < length && list[i] != '\n') ++i;
        name_length = i - start;
        if (name_length > 0u) {
            required += (int32_t)name_length + 1;
            if (value) {
                int32_t at = required - (int32_t)name_length - 1;
                if (required > value_length) {
                    free(list);
                    return -3;
                }
                value[at++] = (UChar)name_length;
                for (size_t j = 0u; j < name_length; ++j) value[at + (int32_t)j] = (UChar)list[start + j];
            }
        }
        if (i < length) ++i;
    }
    free(list);
    return required;
}

int32_t GlobalizationNative_GetLocaleTimeFormat(const UChar* locale, int short_format, UChar* value, int32_t value_length)
{
    char* input = locale_utf8(locale);
    const char* format = short_format ? "H:mm" : "H:mm:ss";
    int32_t result;
    if (input && (strncmp(input, "en", 2u) == 0 || strncmp(input, "root", 4u) == 0)) format = short_format ? "h:mm tt" : "h:mm:ss tt";
    result = copy_utf8(format, strlen(format), value, value_length);
    free(input);
    return result > 0;
}

static int locale_is_english(const UChar* locale)
{
    char* value = locale_utf8(locale);
    int result = value && (strncmp(value, "en", 2u) == 0 || strcmp(value, "root") == 0);
    if (value != (char*)"root") free(value);
    return result;
}

int32_t GlobalizationNative_GetLocaleInfoString(const UChar* locale, LocaleStringData kind, UChar* value, int32_t value_length, const UChar* ui_locale)
{
    char* locale_name = locale_utf8(locale);
    char* ui_name = locale_utf8(ui_locale);
    char buffer[256];
    size_t length = 0u;
    int status = RIN_ICU_STATUS_UNSUPPORTED;
    rin_icu_client_t* client = product_client();
    if (client && (kind == LocaleString_EnglishDisplayName || kind == LocaleString_NativeDisplayName || kind == LocaleString_LocalizedDisplayName ||
                   kind == LocaleString_EnglishLanguageName || kind == LocaleString_NativeLanguageName || kind == LocaleString_LocalizedLanguageName)) {
        uint32_t type = (kind == LocaleString_EnglishDisplayName || kind == LocaleString_LocalizedDisplayName || kind == LocaleString_NativeDisplayName) ? RIN_ICU_DISPLAY_NAME_LANGUAGE : RIN_ICU_DISPLAY_NAME_LANGUAGE;
        status = rin_icu_display_name(client, ui_name, locale_name, type, RIN_ICU_STYLE_LONG, RIN_ICU_LANGUAGE_DISPLAY_STANDARD, buffer, sizeof(buffer), &length);
    }
    if (status != RIN_ICU_STATUS_OK) {
        const char* fallback = ".";
        if (kind == LocaleString_ThousandSeparator || kind == LocaleString_MonetaryThousandSeparator) fallback = ",";
        else if (kind == LocaleString_MonetarySymbol) fallback = locale_is_english(locale) ? "$" : "¤";
        else if (kind == LocaleString_Iso4217MonetarySymbol) fallback = locale_is_english(locale) ? "USD" : "XXX";
        else if (kind == LocaleString_NegativeSign) fallback = "-";
        else if (kind == LocaleString_PositiveSign) fallback = "+";
        else if (kind == LocaleString_PercentSymbol) fallback = "%";
        else if (kind == LocaleString_AMDesignator) fallback = "AM";
        else if (kind == LocaleString_PMDesignator) fallback = "PM";
        else if (kind == LocaleString_Iso639LanguageTwoLetterName) fallback = locale_is_english(locale) ? "en" : "und";
        else if (kind == LocaleString_DecimalSeparator || kind == LocaleString_MonetaryDecimalSeparator) fallback = ".";
        else if (kind == LocaleString_NaNSymbol) fallback = "NaN";
        else if (kind == LocaleString_PositiveInfinitySymbol) fallback = "Infinity";
        else if (kind == LocaleString_NegativeInfinitySymbol) fallback = "-Infinity";
        else if (kind == LocaleString_Digits) fallback = "0\uffff1\uffff2\uffff3\uffff4\uffff5\uffff6\uffff7\uffff8\uffff9";
        length = strlen(fallback);
        if (length >= sizeof(buffer)) length = sizeof(buffer) - 1u;
        memcpy(buffer, fallback, length);
        status = RIN_ICU_STATUS_OK;
    }
    free(locale_name);
    free(ui_name);
    if (status != RIN_ICU_STATUS_OK) return 0;
    return copy_utf8(buffer, length, value, value_length) > 0;
}

int32_t GlobalizationNative_GetLocaleInfoInt(const UChar* locale, LocaleNumberData kind, int32_t* value)
{
    if (!value) return 0;
    switch (kind) {
        case LocaleNumber_MeasurementSystem: *value = locale_is_english(locale) ? 1 : 0; break;
        case LocaleNumber_FirstDayofWeek: *value = locale_is_english(locale) ? 0 : 1; break;
        case LocaleNumber_FractionalDigitsCount:
        case LocaleNumber_MonetaryFractionalDigitsCount: *value = 2; break;
        case LocaleNumber_Monetary: *value = 1; break;
        default: *value = 0; break;
    }
    return 1;
}

int32_t GlobalizationNative_GetLocaleInfoGroupingSizes(const UChar* locale, LocaleNumberData kind, int32_t* primary, int32_t* secondary)
{
    (void)kind;
    if (!primary || !secondary) return 0;
    *primary = 3;
    *secondary = 3;
    if (!locale_is_english(locale)) *secondary = 3;
    return 1;
}

int32_t GlobalizationNative_GetCalendars(const UChar* locale, CalendarId* calendars, int32_t capacity)
{
    (void)locale;
    if (calendars && capacity > 0) calendars[0] = 1;
    return 1;
}

ResultCode GlobalizationNative_GetCalendarInfo(const UChar* locale, CalendarId calendar, CalendarDataType kind, UChar* value, int32_t capacity)
{
    const char* text = "gregorian";
    (void)locale;
    (void)calendar;
    if (kind == CalendarData_MonthDay) text = "M/d";
    else if (kind == CalendarData_ShortDates) text = "M/d/yyyy";
    else if (kind == CalendarData_LongDates) text = "dddd, MMMM d, yyyy";
    else if (kind == CalendarData_YearMonths) text = "MMMM yyyy";
    return copy_utf8(text, strlen(text), value, capacity) > 0 ? Success : InsufficientBuffer;
}

int32_t GlobalizationNative_EnumCalendarInfo(EnumCalendarInfoCallback callback, const UChar* locale, CalendarId calendar, CalendarDataType kind, const void* context)
{
    static const UChar gregorian[] = { 'g','r','e','g','o','r','i','a','n',0 };
    (void)locale;
    (void)calendar;
    (void)kind;
    if (!callback) return 0;
    callback(gregorian, context);
    return 1;
}

int32_t GlobalizationNative_GetLatestJapaneseEra(void)
{
    return 5;
}

int32_t GlobalizationNative_GetJapaneseEraStartDate(int32_t era, int32_t* year, int32_t* month, int32_t* day)
{
    if (!year || !month || !day || era != 5) return 0;
    *year = 2019;
    *month = 5;
    *day = 1;
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

int32_t GlobalizationNative_ToAscii(uint32_t flags, const UChar* source, int32_t source_length, UChar* dest, int32_t dest_length)
{
    (void)flags;
    return copy_ascii_id(source, source_length, dest, dest_length);
}

int32_t GlobalizationNative_ToUnicode(uint32_t flags, const UChar* source, int32_t source_length, UChar* dest, int32_t dest_length)
{
    (void)flags;
    return copy_ascii_id(source, source_length, dest, dest_length);
}

static int timezone_text_call(const UChar* source, UChar* dest, int32_t dest_length, int (*call)(rin_icu_client_t*, const char*, char*, size_t, size_t*))
{
    return locale_call(source, dest, dest_length, call);
}

int32_t GlobalizationNative_WindowsIdToIanaId(const UChar* windows_id, const char* region, UChar* iana_id, int32_t iana_length)
{
    static const UChar eastern[] = { 'A','m','e','r','i','c','a','/','N','e','w','_','Y','o','r','k',0 };
    static const UChar tokyo[] = { 'A','s','i','a','/','T','o','k','y','o',0 };
    static const UChar utc[] = { 'E','t','c','/','U','T','C',0 };
    (void)region;
    if (!windows_id) return 0;
    if (windows_id[0] == 'E' && windows_id[1] == 'a' && windows_id[2] == 's' && windows_id[3] == 't') {
        if (iana_id && iana_length < (int32_t)(sizeof(eastern) / sizeof(eastern[0]))) return 0;
        if (iana_id) memcpy(iana_id, eastern, sizeof(eastern));
        return (int32_t)(sizeof(eastern) / sizeof(eastern[0]) - 1u);
    }
    if (windows_id[0] == 'T' && windows_id[1] == 'o' && windows_id[2] == 'k') {
        if (iana_id && iana_length < (int32_t)(sizeof(tokyo) / sizeof(tokyo[0]))) return 0;
        if (iana_id) memcpy(iana_id, tokyo, sizeof(tokyo));
        return (int32_t)(sizeof(tokyo) / sizeof(tokyo[0]) - 1u);
    }
    if (iana_id && iana_length < (int32_t)(sizeof(utc) / sizeof(utc[0]))) return 0;
    if (iana_id) memcpy(iana_id, utc, sizeof(utc));
    return (int32_t)(sizeof(utc) / sizeof(utc[0]) - 1u);
}

int32_t GlobalizationNative_IanaIdToWindowsId(const UChar* iana_id, UChar* windows_id, int32_t windows_length)
{
    static const UChar eastern[] = { 'E','a','s','t','e','r','n',' ','S','t','a','n','d','a','r','d',' ','T','i','m','e',0 };
    static const UChar tokyo[] = { 'T','o','k','y','o',' ','S','t','a','n','d','a','r','d',' ','T','i','m','e',0 };
    static const UChar utc[] = { 'U','T','C',0 };
    size_t length = u16_length(iana_id, -1);
    const UChar* value = utc;
    if (u16_ascii_equal(iana_id, length, "America/New_York")) value = eastern;
    else if (u16_ascii_equal(iana_id, length, "Asia/Tokyo")) value = tokyo;
    length = u16_length(value, -1);
    if (windows_id && windows_length < (int32_t)length + 1) return 0;
    if (windows_id) memcpy(windows_id, value, (length + 1u) * sizeof(UChar));
    return 1;
}

ResultCode GlobalizationNative_GetTimeZoneDisplayName(const UChar* locale, const UChar* time_zone, TimeZoneDisplayNameType type, UChar* result, int32_t result_length)
{
    (void)locale;
    (void)type;
    return copy_ascii_id(time_zone, (int32_t)u16_length(time_zone, -1), result, result_length) >= 0 ? Success : UnknownError;
}
