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
    char locale[128];
    rin_icu_handle_t option_handles[64];
    uint8_t option_initialized[64];
} SortHandle;

enum
{
    CompareOptionsIgnoreCase = 0x1,
    CompareOptionsIgnoreNonSpace = 0x2,
    CompareOptionsIgnoreSymbols = 0x4,
    CompareOptionsIgnoreKanaType = 0x8,
    CompareOptionsIgnoreWidth = 0x10,
    CompareOptionsNumericOrdering = 0x20,
    CompareOptionsMask = 0x3f
};

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

/* Calendar symbols are product data, not host ICU probes.  The locale record
 * remains the authority for which locale is active; these bounded tables are
 * the supplemental Gregorian/Japanese calendar data shipped with the
 * product.  A language without a table fails closed instead of borrowing the
 * host's current locale. */
static const char* const g_gregorian_era_names[] = { "AD" };
static const char* const g_gregorian_era_abbreviations[] = { "AD" };
static const char* const g_taiwan_era_names[] = { "中華民國" };
static const char* const g_taiwan_era_abbreviations[] = { "民國" };
static const char* const g_korean_era_names[] = { "단기" };
static const char* const g_thai_era_names[] = { "พ.ศ." };
static const char* const g_japanese_era_names_en[] = {
    "Meiji", "Taisho", "Showa", "Heisei", "Reiwa"
};
static const char* const g_japanese_era_names_zh[] = {
    "明治", "大正", "昭和", "平成", "令和"
};
static const char* const g_japanese_era_names_ko[] = {
    "메이지", "다이쇼", "쇼와", "헤이세이", "레이와"
};

static const char* const g_en_month_names[] = {
    "January", "February", "March", "April", "May", "June",
    "July", "August", "September", "October", "November", "December", ""
};
static const char* const g_en_abbreviated_month_names[] = {
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec", ""
};
static const char* const g_en_day_names[] = {
    "Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"
};
static const char* const g_en_abbreviated_day_names[] = {
    "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"
};
static const char* const g_en_super_short_day_names[] = {
    "S", "M", "T", "W", "T", "F", "S"
};

static const char* const g_ja_month_names[] = {
    "1月", "2月", "3月", "4月", "5月", "6月",
    "7月", "8月", "9月", "10月", "11月", "12月", ""
};
static const char* const g_ja_day_names[] = {
    "日曜日", "月曜日", "火曜日", "水曜日", "木曜日", "金曜日", "土曜日"
};
static const char* const g_ja_abbreviated_day_names[] = {
    "日", "月", "火", "水", "木", "金", "土"
};

static const char* const g_zh_month_names[] = {
    "一月", "二月", "三月", "四月", "五月", "六月",
    "七月", "八月", "九月", "十月", "十一月", "十二月", ""
};
static const char* const g_zh_abbreviated_month_names[] = {
    "1月", "2月", "3月", "4月", "5月", "6月",
    "7月", "8月", "9月", "10月", "11月", "12月", ""
};
static const char* const g_zh_day_names[] = {
    "星期日", "星期一", "星期二", "星期三", "星期四", "星期五", "星期六"
};
static const char* const g_zh_abbreviated_day_names[] = {
    "周日", "周一", "周二", "周三", "周四", "周五", "周六"
};
static const char* const g_zh_super_short_day_names[] = {
    "日", "一", "二", "三", "四", "五", "六"
};

static const char* const g_ko_month_names[] = {
    "1월", "2월", "3월", "4월", "5월", "6월",
    "7월", "8월", "9월", "10월", "11월", "12월", ""
};
static const char* const g_ko_day_names[] = {
    "일요일", "월요일", "화요일", "수요일", "목요일", "금요일", "토요일"
};
static const char* const g_ko_abbreviated_day_names[] = {
    "일", "월", "화", "수", "목", "금", "토"
};

static const char* const g_fr_month_names[] = {
    "janvier", "février", "mars", "avril", "mai", "juin",
    "juillet", "août", "septembre", "octobre", "novembre", "décembre", ""
};
static const char* const g_fr_abbreviated_month_names[] = {
    "janv.", "févr.", "mars", "avr.", "mai", "juin",
    "juil.", "août", "sept.", "oct.", "nov.", "déc.", ""
};
static const char* const g_fr_day_names[] = {
    "dimanche", "lundi", "mardi", "mercredi", "jeudi", "vendredi", "samedi"
};
static const char* const g_fr_abbreviated_day_names[] = {
    "dim.", "lun.", "mar.", "mer.", "jeu.", "ven.", "sam."
};
static const char* const g_fr_super_short_day_names[] = {
    "D", "L", "M", "M", "J", "V", "S"
};

static const char* const g_de_month_names[] = {
    "Januar", "Februar", "März", "April", "Mai", "Juni",
    "Juli", "August", "September", "Oktober", "November", "Dezember", ""
};
static const char* const g_de_abbreviated_month_names[] = {
    "Jan.", "Feb.", "März", "Apr.", "Mai", "Juni",
    "Juli", "Aug.", "Sept.", "Okt.", "Nov.", "Dez.", ""
};
static const char* const g_de_day_names[] = {
    "Sonntag", "Montag", "Dienstag", "Mittwoch", "Donnerstag", "Freitag", "Samstag"
};
static const char* const g_de_abbreviated_day_names[] = {
    "So", "Mo", "Di", "Mi", "Do", "Fr", "Sa"
};
static const char* const g_de_super_short_day_names[] = {
    "S", "M", "D", "M", "D", "F", "S"
};

static const char* const g_es_month_names[] = {
    "enero", "febrero", "marzo", "abril", "mayo", "junio",
    "julio", "agosto", "septiembre", "octubre", "noviembre", "diciembre", ""
};
static const char* const g_es_abbreviated_month_names[] = {
    "ene", "feb", "mar", "abr", "may", "jun",
    "jul", "ago", "sep", "oct", "nov", "dic", ""
};
static const char* const g_es_day_names[] = {
    "domingo", "lunes", "martes", "miércoles", "jueves", "viernes", "sábado"
};
static const char* const g_es_abbreviated_day_names[] = {
    "dom", "lun", "mar", "mié", "jue", "vie", "sáb"
};
static const char* const g_es_super_short_day_names[] = {
    "D", "L", "M", "X", "J", "V", "S"
};

static const char* const g_it_month_names[] = {
    "gennaio", "febbraio", "marzo", "aprile", "maggio", "giugno",
    "luglio", "agosto", "settembre", "ottobre", "novembre", "dicembre", ""
};
static const char* const g_it_abbreviated_month_names[] = {
    "gen", "feb", "mar", "apr", "mag", "giu",
    "lug", "ago", "set", "ott", "nov", "dic", ""
};
static const char* const g_it_day_names[] = {
    "domenica", "lunedì", "martedì", "mercoledì", "giovedì", "venerdì", "sabato"
};
static const char* const g_it_abbreviated_day_names[] = {
    "dom", "lun", "mar", "mer", "gio", "ven", "sab"
};
static const char* const g_it_super_short_day_names[] = {
    "D", "L", "M", "M", "G", "V", "S"
};

static const char* const g_pt_month_names[] = {
    "janeiro", "fevereiro", "março", "abril", "maio", "junho",
    "julho", "agosto", "setembro", "outubro", "novembro", "dezembro", ""
};
static const char* const g_pt_abbreviated_month_names[] = {
    "jan", "fev", "mar", "abr", "mai", "jun",
    "jul", "ago", "set", "out", "nov", "dez", ""
};
static const char* const g_pt_day_names[] = {
    "domingo", "segunda-feira", "terça-feira", "quarta-feira",
    "quinta-feira", "sexta-feira", "sábado"
};
static const char* const g_pt_abbreviated_day_names[] = {
    "dom.", "seg.", "ter.", "qua.", "qui.", "sex.", "sáb."
};
static const char* const g_pt_super_short_day_names[] = {
    "D", "S", "T", "Q", "Q", "S", "S"
};

static const char* const g_ru_month_names[] = {
    "январь", "февраль", "март", "апрель", "май", "июнь",
    "июль", "август", "сентябрь", "октябрь", "ноябрь", "декабрь", ""
};
static const char* const g_ru_month_genitive_names[] = {
    "января", "февраля", "марта", "апреля", "мая", "июня",
    "июля", "августа", "сентября", "октября", "ноября", "декабря", ""
};
static const char* const g_ru_abbreviated_month_names[] = {
    "янв.", "февр.", "март", "апр.", "май", "июнь",
    "июль", "авг.", "сент.", "окт.", "нояб.", "дек.", ""
};
static const char* const g_ru_abbreviated_month_genitive_names[] = {
    "янв.", "февр.", "март", "апр.", "май", "июнь",
    "июль", "авг.", "сент.", "окт.", "нояб.", "дек.", ""
};
static const char* const g_ru_day_names[] = {
    "воскресенье", "понедельник", "вторник", "среда", "четверг", "пятница", "суббота"
};
static const char* const g_ru_abbreviated_day_names[] = {
    "вс", "пн", "вт", "ср", "чт", "пт", "сб"
};
static const char* const g_ru_super_short_day_names[] = {
    "В", "П", "В", "С", "Ч", "П", "С"
};

static const char* const g_uk_month_names[] = {
    "січень", "лютий", "березень", "квітень", "травень", "червень",
    "липень", "серпень", "вересень", "жовтень", "листопад", "грудень", ""
};
static const char* const g_uk_abbreviated_month_names[] = {
    "січ", "лют", "бер", "квіт", "трав", "черв",
    "лип", "серп", "вер", "жовт", "лист", "груд", ""
};
static const char* const g_uk_day_names[] = {
    "неділя", "понеділок", "вівторок", "середа", "четвер", "п’ятниця", "субота"
};
static const char* const g_uk_abbreviated_day_names[] = {
    "нд", "пн", "вт", "ср", "чт", "пт", "сб"
};
static const char* const g_uk_super_short_day_names[] = {
    "Н", "П", "В", "С", "Ч", "П", "С"
};

static const char* const g_tr_month_names[] = {
    "Ocak", "Şubat", "Mart", "Nisan", "Mayıs", "Haziran",
    "Temmuz", "Ağustos", "Eylül", "Ekim", "Kasım", "Aralık", ""
};
static const char* const g_tr_abbreviated_month_names[] = {
    "Oca", "Şub", "Mar", "Nis", "May", "Haz",
    "Tem", "Ağu", "Eyl", "Eki", "Kas", "Ara", ""
};
static const char* const g_tr_day_names[] = {
    "Pazar", "Pazartesi", "Salı", "Çarşamba", "Perşembe", "Cuma", "Cumartesi"
};
static const char* const g_tr_abbreviated_day_names[] = {
    "Paz", "Pzt", "Sal", "Çar", "Per", "Cum", "Cmt"
};
static const char* const g_tr_super_short_day_names[] = {
    "P", "P", "S", "Ç", "P", "C", "C"
};

static const char* const g_pl_month_names[] = {
    "styczeń", "luty", "marzec", "kwiecień", "maj", "czerwiec",
    "lipiec", "sierpień", "wrzesień", "październik", "listopad", "grudzień", ""
};
static const char* const g_pl_abbreviated_month_names[] = {
    "sty", "lut", "mar", "kwi", "maj", "cze",
    "lip", "sie", "wrz", "paź", "lis", "gru", ""
};
static const char* const g_pl_day_names[] = {
    "niedziela", "poniedziałek", "wtorek", "środa", "czwartek", "piątek", "sobota"
};
static const char* const g_pl_abbreviated_day_names[] = {
    "ndz", "pon", "wt", "śr", "czw", "pt", "sob"
};
static const char* const g_pl_super_short_day_names[] = {
    "N", "P", "W", "Ś", "C", "P", "S"
};

static const char* const g_nl_month_names[] = {
    "januari", "februari", "maart", "april", "mei", "juni",
    "juli", "augustus", "september", "oktober", "november", "december", ""
};
static const char* const g_nl_abbreviated_month_names[] = {
    "jan", "feb", "mrt", "apr", "mei", "jun",
    "jul", "aug", "sep", "okt", "nov", "dec", ""
};
static const char* const g_nl_day_names[] = {
    "zondag", "maandag", "dinsdag", "woensdag", "donderdag", "vrijdag", "zaterdag"
};
static const char* const g_nl_abbreviated_day_names[] = {
    "zo", "ma", "di", "wo", "do", "vr", "za"
};
static const char* const g_nl_super_short_day_names[] = {
    "Z", "M", "D", "W", "D", "V", "Z"
};

static const char* const g_sv_month_names[] = {
    "januari", "februari", "mars", "april", "maj", "juni",
    "juli", "augusti", "september", "oktober", "november", "december", ""
};
static const char* const g_sv_abbreviated_month_names[] = {
    "jan", "feb", "mar", "apr", "maj", "jun",
    "jul", "aug", "sep", "okt", "nov", "dec", ""
};
static const char* const g_sv_day_names[] = {
    "söndag", "måndag", "tisdag", "onsdag", "torsdag", "fredag", "lördag"
};
static const char* const g_sv_abbreviated_day_names[] = {
    "sön", "mån", "tis", "ons", "tor", "fre", "lör"
};
static const char* const g_sv_super_short_day_names[] = {
    "S", "M", "T", "O", "T", "F", "L"
};

static const char* const g_fi_month_names[] = {
    "tammikuu", "helmikuu", "maaliskuu", "huhtikuu", "toukokuu", "kesäkuu",
    "heinäkuu", "elokuu", "syyskuu", "lokakuu", "marraskuu", "joulukuu", ""
};
static const char* const g_fi_abbreviated_month_names[] = {
    "tammi", "helmi", "maalis", "huhti", "touko", "kesä",
    "heinä", "elo", "syys", "loka", "marras", "joulu", ""
};
static const char* const g_fi_day_names[] = {
    "sunnuntai", "maanantai", "tiistai", "keskiviikko", "torstai", "perjantai", "lauantai"
};
static const char* const g_fi_abbreviated_day_names[] = {
    "su", "ma", "ti", "ke", "to", "pe", "la"
};
static const char* const g_fi_super_short_day_names[] = {
    "S", "M", "T", "K", "T", "P", "L"
};

static const char* const g_da_month_names[] = {
    "januar", "februar", "marts", "april", "maj", "juni",
    "juli", "august", "september", "oktober", "november", "december", ""
};
static const char* const g_da_abbreviated_month_names[] = {
    "jan", "feb", "mar", "apr", "maj", "jun",
    "jul", "aug", "sep", "okt", "nov", "dec", ""
};
static const char* const g_da_day_names[] = {
    "søndag", "mandag", "tirsdag", "onsdag", "torsdag", "fredag", "lørdag"
};
static const char* const g_da_abbreviated_day_names[] = {
    "søn", "man", "tir", "ons", "tor", "fre", "lør"
};
static const char* const g_da_super_short_day_names[] = {
    "S", "M", "T", "O", "T", "F", "L"
};

static const char* const g_cs_month_names[] = {
    "leden", "únor", "březen", "duben", "květen", "červen",
    "červenec", "srpen", "září", "říjen", "listopad", "prosinec", ""
};
static const char* const g_cs_abbreviated_month_names[] = {
    "led", "úno", "bře", "dub", "kvě", "čvn",
    "čvc", "srp", "zář", "říj", "lis", "pro", ""
};
static const char* const g_cs_day_names[] = {
    "neděle", "pondělí", "úterý", "středa", "čtvrtek", "pátek", "sobota"
};
static const char* const g_cs_abbreviated_day_names[] = {
    "ne", "po", "út", "st", "čt", "pá", "so"
};
static const char* const g_cs_super_short_day_names[] = {
    "N", "P", "Ú", "S", "Č", "P", "S"
};

static const char* const g_hu_month_names[] = {
    "január", "február", "március", "április", "május", "június",
    "július", "augusztus", "szeptember", "október", "november", "december", ""
};
static const char* const g_hu_abbreviated_month_names[] = {
    "jan.", "febr.", "márc.", "ápr.", "máj.", "jún.",
    "júl.", "aug.", "szept.", "okt.", "nov.", "dec.", ""
};
static const char* const g_hu_day_names[] = {
    "vasárnap", "hétfő", "kedd", "szerda", "csütörtök", "péntek", "szombat"
};
static const char* const g_hu_abbreviated_day_names[] = {
    "V", "H", "K", "Sze", "Cs", "P", "Szo"
};
static const char* const g_hu_super_short_day_names[] = {
    "V", "H", "K", "S", "C", "P", "S"
};

static const char* const g_ro_month_names[] = {
    "ianuarie", "februarie", "martie", "aprilie", "mai", "iunie",
    "iulie", "august", "septembrie", "octombrie", "noiembrie", "decembrie", ""
};
static const char* const g_ro_abbreviated_month_names[] = {
    "ian.", "feb.", "mar.", "apr.", "mai", "iun.",
    "iul.", "aug.", "sept.", "oct.", "nov.", "dec.", ""
};
static const char* const g_ro_day_names[] = {
    "duminică", "luni", "marți", "miercuri", "joi", "vineri", "sâmbătă"
};
static const char* const g_ro_abbreviated_day_names[] = {
    "dum", "lun", "mar", "mie", "joi", "vin", "sâm"
};
static const char* const g_ro_super_short_day_names[] = {
    "D", "L", "M", "M", "J", "V", "S"
};

static const char* const g_ar_month_names[] = {
    "يناير", "فبراير", "مارس", "أبريل", "مايو", "يونيو",
    "يوليو", "أغسطس", "سبتمبر", "أكتوبر", "نوفمبر", "ديسمبر", ""
};
static const char* const g_ar_abbreviated_month_names[] = {
    "يناير", "فبراير", "مارس", "أبريل", "مايو", "يونيو",
    "يوليو", "أغسطس", "سبتمبر", "أكتوبر", "نوفمبر", "ديسمبر", ""
};
static const char* const g_ar_day_names[] = {
    "الأحد", "الاثنين", "الثلاثاء", "الأربعاء", "الخميس", "الجمعة", "السبت"
};
static const char* const g_ar_abbreviated_day_names[] = {
    "أحد", "اثن", "ثلا", "أرب", "خمي", "جمع", "سبت"
};
static const char* const g_ar_super_short_day_names[] = {
    "ح", "ن", "ث", "ر", "خ", "ج", "س"
};
static const char* const g_ar_hijri_month_names[] = {
    "محرم", "صفر", "ربيع الأول", "ربيع الآخر", "جمادى الأولى", "جمادى الآخرة",
    "رجب", "شعبان", "رمضان", "شوال", "ذو القعدة", "ذو الحجة", ""
};
static const char* const g_ar_hijri_abbreviated_month_names[] = {
    "محرم", "صفر", "ربيع 1", "ربيع 2", "جمادى 1", "جمادى 2",
    "رجب", "شعبان", "رمضان", "شوال", "ذو القعدة", "ذو الحجة", ""
};
static const char* const g_hijri_era_names[] = { "بعد الهجرة" };
static const char* const g_hijri_era_abbreviations[] = { "هـ" };

static const char* const g_fa_gregorian_month_names[] = {
    "ژانویه", "فوریه", "مارس", "آوریل", "مه", "ژوئن",
    "ژوئیه", "اوت", "سپتامبر", "اکتبر", "نوامبر", "دسامبر", ""
};
static const char* const g_fa_gregorian_abbreviated_month_names[] = {
    "ژانویه", "فوریه", "مارس", "آوریل", "مه", "ژوئن",
    "ژوئیه", "اوت", "سپتامبر", "اکتبر", "نوامبر", "دسامبر", ""
};
static const char* const g_fa_month_names[] = {
    "فروردین", "اردیبهشت", "خرداد", "تیر", "مرداد", "شهریور",
    "مهر", "آبان", "آذر", "دی", "بهمن", "اسفند", ""
};
static const char* const g_fa_abbreviated_month_names[] = {
    "فرو", "ارد", "خرد", "تیر", "مرد", "شهر",
    "مهر", "آبا", "آذر", "دی", "بهم", "اسف", ""
};
static const char* const g_fa_day_names[] = {
    "یکشنبه", "دوشنبه", "سه‌شنبه", "چهارشنبه", "پنجشنبه", "جمعه", "شنبه"
};
static const char* const g_fa_abbreviated_day_names[] = {
    "یکش", "دوش", "سه‌ش", "چها", "پنج", "جمع", "شنبه"
};
static const char* const g_fa_super_short_day_names[] = {
    "ی", "د", "س", "چ", "پ", "ج", "ش"
};

static const char* const g_persian_era_names[] = { "ه.ش" };
static const char* const g_persian_era_abbreviations[] = { "ه.ش" };

static const char* const g_he_month_names[] = {
    "ינואר", "פברואר", "מרץ", "אפריל", "מאי", "יוני",
    "יולי", "אוגוסט", "ספטמבר", "אוקטובר", "נובמבר", "דצמבר", ""
};
static const char* const g_he_abbreviated_month_names[] = {
    "ינו׳", "פבר׳", "מרץ", "אפר׳", "מאי", "יוני",
    "יולי", "אוג׳", "ספט׳", "אוק׳", "נוב׳", "דצמ׳", ""
};
static const char* const g_he_day_names[] = {
    "יום ראשון", "יום שני", "יום שלישי", "יום רביעי",
    "יום חמישי", "יום שישי", "שבת"
};
static const char* const g_he_abbreviated_day_names[] = {
    "יום א׳", "יום ב׳", "יום ג׳", "יום ד׳", "יום ה׳", "יום ו׳", "שבת"
};
static const char* const g_he_super_short_day_names[] = {
    "א", "ב", "ג", "ד", "ה", "ו", "ש"
};
static const char* const g_hebrew_month_names[] = {
    "תשרי", "חשוון", "כסלו", "טבת", "שבט", "אדר א׳", "אדר",
    "ניסן", "אייר", "סיוון", "תמוז", "אב", "אלול", "אדר ב׳"
};
static const char* const g_hebrew_abbreviated_month_names[] = {
    "תשרי", "חשוון", "כסלו", "טבת", "שבט", "אדר א׳", "אדר",
    "ניסן", "אייר", "סיוון", "תמוז", "אב", "אלול", "אדר ב׳"
};
static const char* const g_hebrew_era_names[] = { "AM" };
static const char* const g_hebrew_era_abbreviations[] = { "AM" };

static const char* const g_hi_month_names[] = {
    "जनवरी", "फ़रवरी", "मार्च", "अप्रैल", "मई", "जून",
    "जुलाई", "अगस्त", "सितंबर", "अक्तूबर", "नवंबर", "दिसंबर", ""
};
static const char* const g_hi_abbreviated_month_names[] = {
    "जन॰", "फ़र॰", "मार्च", "अप्रैल", "मई", "जून",
    "जुलाई", "अग॰", "सित॰", "अक्तू॰", "नव॰", "दिस॰", ""
};
static const char* const g_hi_day_names[] = {
    "रविवार", "सोमवार", "मंगलवार", "बुधवार", "गुरुवार", "शुक्रवार", "शनिवार"
};
static const char* const g_hi_abbreviated_day_names[] = {
    "रवि", "सोम", "मंगल", "बुध", "गुरु", "शुक्र", "शनि"
};
static const char* const g_hi_super_short_day_names[] = {
    "र", "सो", "मं", "बु", "गु", "शु", "श"
};

static const char* const g_th_month_names[] = {
    "มกราคม", "กุมภาพันธ์", "มีนาคม", "เมษายน", "พฤษภาคม", "มิถุนายน",
    "กรกฎาคม", "สิงหาคม", "กันยายน", "ตุลาคม", "พฤศจิกายน", "ธันวาคม", ""
};
static const char* const g_th_abbreviated_month_names[] = {
    "ม.ค.", "ก.พ.", "มี.ค.", "เม.ย.", "พ.ค.", "มิ.ย.",
    "ก.ค.", "ส.ค.", "ก.ย.", "ต.ค.", "พ.ย.", "ธ.ค.", ""
};
static const char* const g_th_day_names[] = {
    "อาทิตย์", "จันทร์", "อังคาร", "พุธ", "พฤหัสบดี", "ศุกร์", "เสาร์"
};
static const char* const g_th_abbreviated_day_names[] = {
    "อา.", "จ.", "อ.", "พ.", "พฤ.", "ศ.", "ส."
};
static const char* const g_th_super_short_day_names[] = {
    "อ", "จ", "อ", "พ", "พ", "ศ", "ส"
};

static const char* const g_id_month_names[] = {
    "Januari", "Februari", "Maret", "April", "Mei", "Juni",
    "Juli", "Agustus", "September", "Oktober", "November", "Desember", ""
};
static const char* const g_id_abbreviated_month_names[] = {
    "Jan", "Feb", "Mar", "Apr", "Mei", "Jun",
    "Jul", "Agu", "Sep", "Okt", "Nov", "Des", ""
};
static const char* const g_id_day_names[] = {
    "Minggu", "Senin", "Selasa", "Rabu", "Kamis", "Jumat", "Sabtu"
};
static const char* const g_id_abbreviated_day_names[] = {
    "Min", "Sen", "Sel", "Rab", "Kam", "Jum", "Sab"
};
static const char* const g_id_super_short_day_names[] = {
    "M", "S", "S", "R", "K", "J", "S"
};

static const char* const g_vi_month_names[] = {
    "tháng 1", "tháng 2", "tháng 3", "tháng 4", "tháng 5", "tháng 6",
    "tháng 7", "tháng 8", "tháng 9", "tháng 10", "tháng 11", "tháng 12", ""
};
static const char* const g_vi_abbreviated_month_names[] = {
    "T1", "T2", "T3", "T4", "T5", "T6",
    "T7", "T8", "T9", "T10", "T11", "T12", ""
};
static const char* const g_vi_day_names[] = {
    "Chủ Nhật", "Thứ Hai", "Thứ Ba", "Thứ Tư", "Thứ Năm", "Thứ Sáu", "Thứ Bảy"
};
static const char* const g_vi_abbreviated_day_names[] = {
    "CN", "T2", "T3", "T4", "T5", "T6", "T7"
};
static const char* const g_vi_super_short_day_names[] = {
    "C", "H", "B", "T", "N", "S", "B"
};

typedef struct RinCalendarSymbols
{
    const char* language;
    const char* const* month_names;
    const char* const* abbreviated_month_names;
    const char* const* day_names;
    const char* const* abbreviated_day_names;
    const char* const* super_short_day_names;
    const char* native_gregorian_name;
    const char* native_japanese_name;
    const char* const* japanese_era_names;
    const char* const* japanese_era_abbreviations;
    const char* const* month_genitive_names;
    const char* const* abbreviated_month_genitive_names;
} RinCalendarSymbols;

static const RinCalendarSymbols g_calendar_symbols[] = {
    { "en", g_en_month_names, g_en_abbreviated_month_names, g_en_day_names,
      g_en_abbreviated_day_names, g_en_super_short_day_names, "Gregorian Calendar", "Japanese Calendar",
      g_japanese_era_names_en, g_japanese_era_abbreviations, NULL, NULL },
    { "ja", g_ja_month_names, g_ja_month_names, g_ja_day_names,
      g_ja_abbreviated_day_names, g_ja_abbreviated_day_names, "西暦", "和暦",
      g_japanese_era_names, g_japanese_era_abbreviations, NULL, NULL },
    { "zh", g_zh_month_names, g_zh_abbreviated_month_names, g_zh_day_names,
      g_zh_abbreviated_day_names, g_zh_super_short_day_names, "公历", "日本历",
      g_japanese_era_names_zh, g_japanese_era_abbreviations, NULL, NULL },
    { "ko", g_ko_month_names, g_ko_month_names, g_ko_day_names,
      g_ko_abbreviated_day_names, g_ko_abbreviated_day_names, "그레고리력", "일본력",
      g_japanese_era_names_ko, g_japanese_era_abbreviations, NULL, NULL },
    { "fr", g_fr_month_names, g_fr_abbreviated_month_names, g_fr_day_names,
      g_fr_abbreviated_day_names, g_fr_super_short_day_names, "calendrier grégorien", "calendrier japonais",
      g_japanese_era_names_en, g_japanese_era_abbreviations, NULL, NULL },
    { "de", g_de_month_names, g_de_abbreviated_month_names, g_de_day_names,
      g_de_abbreviated_day_names, g_de_super_short_day_names, "Gregorianischer Kalender", "Japanischer Kalender",
      g_japanese_era_names_en, g_japanese_era_abbreviations, NULL, NULL },
    { "es", g_es_month_names, g_es_abbreviated_month_names, g_es_day_names,
      g_es_abbreviated_day_names, g_es_super_short_day_names, "calendario gregoriano", "calendario japonés",
      g_japanese_era_names_en, g_japanese_era_abbreviations, NULL, NULL },
    { "it", g_it_month_names, g_it_abbreviated_month_names, g_it_day_names,
      g_it_abbreviated_day_names, g_it_super_short_day_names, "calendario gregoriano", "calendario giapponese",
      g_japanese_era_names_en, g_japanese_era_abbreviations, NULL, NULL },
    { "pt", g_pt_month_names, g_pt_abbreviated_month_names, g_pt_day_names,
      g_pt_abbreviated_day_names, g_pt_super_short_day_names, "calendário gregoriano", "calendário japonês",
      g_japanese_era_names_en, g_japanese_era_abbreviations, NULL, NULL },
    { "ru", g_ru_month_names, g_ru_abbreviated_month_names, g_ru_day_names,
      g_ru_abbreviated_day_names, g_ru_super_short_day_names, "григорианский календарь", "японский календарь",
      g_japanese_era_names_en, g_japanese_era_abbreviations, g_ru_month_genitive_names,
      g_ru_abbreviated_month_genitive_names },
    { "uk", g_uk_month_names, g_uk_abbreviated_month_names, g_uk_day_names,
      g_uk_abbreviated_day_names, g_uk_super_short_day_names, "григоріанський календар", "японський календар",
      g_japanese_era_names_en, g_japanese_era_abbreviations, NULL, NULL },
    { "tr", g_tr_month_names, g_tr_abbreviated_month_names, g_tr_day_names,
      g_tr_abbreviated_day_names, g_tr_super_short_day_names, "Miladi Takvim", "Japon Takvimi",
      g_japanese_era_names_en, g_japanese_era_abbreviations, NULL, NULL },
    { "pl", g_pl_month_names, g_pl_abbreviated_month_names, g_pl_day_names,
      g_pl_abbreviated_day_names, g_pl_super_short_day_names, "Kalendarz gregoriański", "Kalendarz japoński",
      g_japanese_era_names_en, g_japanese_era_abbreviations, NULL, NULL },
    { "nl", g_nl_month_names, g_nl_abbreviated_month_names, g_nl_day_names,
      g_nl_abbreviated_day_names, g_nl_super_short_day_names, "Gregoriaanse kalender", "Japanse kalender",
      g_japanese_era_names_en, g_japanese_era_abbreviations, NULL, NULL },
    { "sv", g_sv_month_names, g_sv_abbreviated_month_names, g_sv_day_names,
      g_sv_abbreviated_day_names, g_sv_super_short_day_names, "Gregoriansk kalender", "Japansk kalender",
      g_japanese_era_names_en, g_japanese_era_abbreviations, NULL, NULL },
    { "fi", g_fi_month_names, g_fi_abbreviated_month_names, g_fi_day_names,
      g_fi_abbreviated_day_names, g_fi_super_short_day_names, "Gregorinen kalenteri", "Japanilainen kalenteri",
      g_japanese_era_names_en, g_japanese_era_abbreviations, NULL, NULL },
    { "da", g_da_month_names, g_da_abbreviated_month_names, g_da_day_names,
      g_da_abbreviated_day_names, g_da_super_short_day_names, "gregoriansk kalender", "japansk kalender",
      g_japanese_era_names_en, g_japanese_era_abbreviations, NULL, NULL },
    { "cs", g_cs_month_names, g_cs_abbreviated_month_names, g_cs_day_names,
      g_cs_abbreviated_day_names, g_cs_super_short_day_names, "gregoriánský kalendář", "japonský kalendář",
      g_japanese_era_names_en, g_japanese_era_abbreviations, NULL, NULL },
    { "hu", g_hu_month_names, g_hu_abbreviated_month_names, g_hu_day_names,
      g_hu_abbreviated_day_names, g_hu_super_short_day_names, "Gergely-naptár", "Japán naptár",
      g_japanese_era_names_en, g_japanese_era_abbreviations, NULL, NULL },
    { "ro", g_ro_month_names, g_ro_abbreviated_month_names, g_ro_day_names,
      g_ro_abbreviated_day_names, g_ro_super_short_day_names, "calendarul gregorian", "calendarul japonez",
      g_japanese_era_names_en, g_japanese_era_abbreviations, NULL, NULL },
    { "ar", g_ar_month_names, g_ar_abbreviated_month_names, g_ar_day_names,
      g_ar_abbreviated_day_names, g_ar_super_short_day_names, "التقويم الميلادي", "التقويم الياباني",
      g_japanese_era_names_en, g_japanese_era_abbreviations, NULL, NULL },
    { "fa", g_fa_gregorian_month_names, g_fa_gregorian_abbreviated_month_names, g_fa_day_names,
      g_fa_abbreviated_day_names, g_fa_super_short_day_names, "تقویم میلادی", "تقویم ژاپنی",
      g_japanese_era_names_en, g_japanese_era_abbreviations, NULL, NULL },
    { "he", g_he_month_names, g_he_abbreviated_month_names, g_he_day_names,
      g_he_abbreviated_day_names, g_he_super_short_day_names, "הלוח הגרגוריאני", "הלוח היפני",
      g_japanese_era_names_en, g_japanese_era_abbreviations, NULL, NULL },
    { "hi", g_hi_month_names, g_hi_abbreviated_month_names, g_hi_day_names,
      g_hi_abbreviated_day_names, g_hi_super_short_day_names, "ग्रेगोरियन कैलेंडर", "जापानी कैलेंडर",
      g_japanese_era_names_en, g_japanese_era_abbreviations, NULL, NULL },
    { "th", g_th_month_names, g_th_abbreviated_month_names, g_th_day_names,
      g_th_abbreviated_day_names, g_th_super_short_day_names, "ปฏิทินเกรกอเรียน", "ปฏิทินญี่ปุ่น",
      g_japanese_era_names_en, g_japanese_era_abbreviations, NULL, NULL },
    { "id", g_id_month_names, g_id_abbreviated_month_names, g_id_day_names,
      g_id_abbreviated_day_names, g_id_super_short_day_names, "Kalender Gregorian", "Kalender Jepang",
      g_japanese_era_names_en, g_japanese_era_abbreviations, NULL, NULL },
    { "vi", g_vi_month_names, g_vi_abbreviated_month_names, g_vi_day_names,
      g_vi_abbreviated_day_names, g_vi_super_short_day_names, "Lịch Gregory", "Lịch Nhật Bản",
      g_japanese_era_names_en, g_japanese_era_abbreviations, NULL, NULL },
};

static const RinCalendarSymbols* calendar_symbols_for_language(const char* language)
{
    size_t index;
    if (!language || language[0] == '\0') language = "en";
    for (index = 0u; index < sizeof(g_calendar_symbols) / sizeof(g_calendar_symbols[0]); ++index) {
        if (strcmp(g_calendar_symbols[index].language, language) == 0) return &g_calendar_symbols[index];
    }
    return NULL;
}

static int is_product_gregorian_calendar(CalendarId calendar)
{
    switch (calendar) {
        case 1:  /* Gregorian (localized) */
        case 2:  /* Gregorian (U.S.) */
        case 9:  /* Gregorian Middle East French */
        case 10: /* Gregorian Arabic */
        case 11: /* Gregorian transliterated English */
        case 12: /* Gregorian transliterated French */
        case 13: /* Julian: managed data uses Gregorian-shaped fields */
            return 1;
        default:
            return 0;
    }
}

static int is_product_calendar(CalendarId calendar)
{
    return is_product_gregorian_calendar(calendar) || calendar == 3;
}

static int is_product_calendar_for_locale(const RinIcuDataLocaleRecord* record,
                                          CalendarId calendar)
{
    if (!record) return 0;
    if (is_product_calendar(calendar)) return 1;
    if (calendar == 4) {
        return strcmp(record->language, "zh") == 0 &&
            strcmp(record->region, "TW") == 0;
    }
    if (calendar == 5) {
        return strcmp(record->language, "ko") == 0 &&
            strcmp(record->region, "KR") == 0;
    }
    if (calendar == 7) {
        return strcmp(record->language, "th") == 0 &&
            strcmp(record->region, "TH") == 0;
    }
    if (calendar == 6 || calendar == 23) {
        return strcmp(record->language, "ar") == 0 &&
            strcmp(record->region, "SA") == 0;
    }
    if (calendar == 22) {
        return strcmp(record->language, "fa") == 0 &&
            strcmp(record->region, "IR") == 0;
    }
    if (calendar == 8) {
        return strcmp(record->language, "he") == 0 &&
            strcmp(record->region, "IL") == 0;
    }
    return 0;
}

static const char* calendar_native_name(const RinIcuDataLocaleRecord* record,
                                        CalendarId calendar)
{
    const RinCalendarSymbols* symbols =
        record ? calendar_symbols_for_language(record->language) : NULL;
    if (!symbols) return NULL;
    switch (calendar) {
        case 3: return symbols->native_japanese_name;
        case 4: return "中華民國曆";
        case 5: return "단기력";
        case 7: return "ปฏิทินพุทธ";
        case 22: return "تقویم هجری شمسی";
        case 6: return "التقويم الهجري";
        case 23: return "تقويم أم القرى";
        case 8: return "הלוח העברי";
        default: return symbols->native_gregorian_name;
    }
}

static const char* calendar_symbol(const RinIcuDataLocaleRecord* record,
                                   CalendarId calendar, CalendarDataType kind,
                                   size_t index)
{
    const RinCalendarSymbols* symbols;
    if (!record || !is_product_calendar_for_locale(record, calendar)) return NULL;
    symbols = calendar_symbols_for_language(record->language);
    if (!symbols) return NULL;
    if (kind == CalendarData_NativeName) {
        return index == 0u ? calendar_native_name(record, calendar) : NULL;
    }
    if (kind == CalendarData_EraNames || kind == CalendarData_AbbrevEraNames) {
        const char* const* eras;
        size_t count;
        if (calendar == 3) {
            eras = kind == CalendarData_EraNames
                ? symbols->japanese_era_names : symbols->japanese_era_abbreviations;
            count = sizeof(g_japanese_eras) / sizeof(g_japanese_eras[0]);
        } else if (calendar == 4) {
            eras = kind == CalendarData_EraNames
                ? g_taiwan_era_names : g_taiwan_era_abbreviations;
            count = 1u;
        } else if (calendar == 5) {
            eras = g_korean_era_names;
            count = 1u;
        } else if (calendar == 7) {
            eras = g_thai_era_names;
            count = 1u;
        } else if (calendar == 22) {
            eras = kind == CalendarData_EraNames
                ? g_persian_era_names : g_persian_era_abbreviations;
            count = 1u;
        } else if (calendar == 6 || calendar == 23) {
            eras = kind == CalendarData_EraNames
                ? g_hijri_era_names : g_hijri_era_abbreviations;
            count = 1u;
        } else if (calendar == 8) {
            eras = kind == CalendarData_EraNames
                ? g_hebrew_era_names : g_hebrew_era_abbreviations;
            count = 1u;
        } else {
            eras = kind == CalendarData_EraNames
                ? g_gregorian_era_names : g_gregorian_era_abbreviations;
            count = 1u;
        }
        return index < count ? eras[index] : NULL;
    }
    if (calendar == 6 || calendar == 23) {
        if (kind == CalendarData_MonthNames) {
            return index < 13u ? g_ar_hijri_month_names[index] : NULL;
        }
        if (kind == CalendarData_AbbrevMonthNames) {
            return index < 13u ? g_ar_hijri_abbreviated_month_names[index] : NULL;
        }
        if (kind == CalendarData_MonthGenitiveNames) {
            return index < 13u ? g_ar_hijri_month_names[index] : NULL;
        }
        if (kind == CalendarData_AbbrevMonthGenitiveNames) {
            return index < 13u ? g_ar_hijri_abbreviated_month_names[index] : NULL;
        }
    }
    if (calendar == 22) {
        if (kind == CalendarData_MonthNames || kind == CalendarData_MonthGenitiveNames) {
            return index < 13u ? g_fa_month_names[index] : NULL;
        }
        if (kind == CalendarData_AbbrevMonthNames || kind == CalendarData_AbbrevMonthGenitiveNames) {
            return index < 13u ? g_fa_abbreviated_month_names[index] : NULL;
        }
    }
    if (calendar == 8) {
        if (kind == CalendarData_MonthNames || kind == CalendarData_MonthGenitiveNames) {
            return index < 14u ? g_hebrew_month_names[index] : NULL;
        }
        if (kind == CalendarData_AbbrevMonthNames || kind == CalendarData_AbbrevMonthGenitiveNames) {
            return index < 14u ? g_hebrew_abbreviated_month_names[index] : NULL;
        }
    }
    if (kind == CalendarData_MonthNames) {
        return index < 13u ? symbols->month_names[index] : NULL;
    }
    if (kind == CalendarData_MonthGenitiveNames) {
        return index < 13u ? (symbols->month_genitive_names ? symbols->month_genitive_names[index] : symbols->month_names[index]) : NULL;
    }
    if (kind == CalendarData_AbbrevMonthNames) {
        return index < 13u ? symbols->abbreviated_month_names[index] : NULL;
    }
    if (kind == CalendarData_AbbrevMonthGenitiveNames) {
        return index < 13u ? (symbols->abbreviated_month_genitive_names ? symbols->abbreviated_month_genitive_names[index] : symbols->abbreviated_month_names[index]) : NULL;
    }
    if (kind == CalendarData_DayNames) {
        return index < 7u ? symbols->day_names[index] : NULL;
    }
    if (kind == CalendarData_SuperShortDayNames) {
        return index < 7u ? symbols->super_short_day_names[index] : NULL;
    }
    if (kind == CalendarData_AbbrevDayNames) {
        return index < 7u ? symbols->abbreviated_day_names[index] : NULL;
    }
    return NULL;
}

static size_t calendar_symbol_count(CalendarId calendar, CalendarDataType kind)
{
    if (kind == CalendarData_EraNames || kind == CalendarData_AbbrevEraNames) {
        return calendar == 3 ? sizeof(g_japanese_eras) / sizeof(g_japanese_eras[0]) : 1u;
    }
    if (kind == CalendarData_MonthNames || kind == CalendarData_AbbrevMonthNames ||
        kind == CalendarData_MonthGenitiveNames || kind == CalendarData_AbbrevMonthGenitiveNames) {
        return calendar == 8 ? 14u : 13u;
    }
    if (kind == CalendarData_DayNames || kind == CalendarData_AbbrevDayNames ||
        kind == CalendarData_SuperShortDayNames) return 7u;
    return kind == CalendarData_NativeName ? 1u : 0u;
}

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
    size_t limit = RIN_ICU_MAX_CSTRING_BYTES / sizeof(UChar);
    if (!value) return 0u;
    if (length >= 0) return (size_t)length;
    if (length != -1) return SIZE_MAX;
    while (result < limit && value[result] != 0u) ++result;
    return result < limit ? result : SIZE_MAX;
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
    if (!value || value_length < -1) return NULL;
    length = u16_length(value, value_length);
    if (length == SIZE_MAX) return NULL;
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
        size_t addition;
        if (!decode_utf8((const unsigned char*)value, value_length, &offset, &cp)) return 0;
        addition = cp <= 0xffffu ? 1u : 2u;
        if (required > SIZE_MAX - addition) return 0;
        required += addition;
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

/* PAL string-returning entry points receive a caller-owned buffer and expose
 * success as a boolean/result code. Keep the length-based copy above for
 * NormalizeString and IDNA, but terminate string-producing paths here. An
 * empty string is valid, so -1 is reserved for conversion/capacity failure. */
static int copy_utf8_z(const char* value, size_t length, UChar* dest, int32_t capacity)
{
    int32_t written = 0;
    if (!value || !utf8_to_utf16(value, length, NULL, 0, &written)) return -1;
    if (!dest) return written;
    if (capacity <= 0 || written >= capacity) return -1;
    if (!utf8_to_utf16(value, length, dest, capacity - 1, &written)) return -1;
    dest[written] = 0u;
    return written;
}

static ResultCode copy_calendar_text(const char* text,
                                     UChar* value,
                                     int32_t capacity,
                                     int32_t* out_length)
{
    int32_t required = 0;
    if (!text || capacity < 0 ||
        !utf8_to_utf16(text, strlen(text), NULL, 0, &required)) return UnknownError;
    if (out_length) *out_length = required;
    if (!value || required >= capacity) return InsufficientBuffer;
    return copy_utf8_z(text, strlen(text), value, capacity) >= 0
        ? Success
        : UnknownError;
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

static int product_locale_language_id(const char* locale_id)
{
    struct LocaleIdEntry {
        const char* name;
        int value;
    };
    static const struct LocaleIdEntry entries[] = {
        {"en-US", 0x0409}, {"en-GB", 0x0809}, {"en-IN", 0x4009}, {"ja-JP", 0x0411},
        {"zh-CN", 0x0804}, {"zh-TW", 0x0404}, {"ko-KR", 0x0412},
        {"fr-FR", 0x040c}, {"fr-BE", 0x080c}, {"de-DE", 0x0407}, {"de-AT", 0x0c07}, {"es-ES", 0x0c0a},
        {"es-MX", 0x080a}, {"es-US", 0x540a}, {"it-IT", 0x0410}, {"pt-BR", 0x0416},
        {"pt-PT", 0x0816}, {"ru-RU", 0x0419}, {"uk-UA", 0x0422},
        {"tr-TR", 0x041f}, {"pl-PL", 0x0415}, {"nl-NL", 0x0413},
        {"sv-SE", 0x041d}, {"fi-FI", 0x040b}, {"da-DK", 0x0406},
        {"cs-CZ", 0x0405}, {"hu-HU", 0x040e}, {"ro-RO", 0x0418},
        {"ar-SA", 0x0401}, {"fa-IR", 0x0429}, {"he-IL", 0x040d}, {"hi-IN", 0x0439}, {"th-TH", 0x041e},
        {"id-ID", 0x0421}, {"vi-VN", 0x042a}
    };
    size_t index;
    if (!locale_id || locale_id[0] == '\0') return 0;
    for (index = 0u; index < sizeof(entries) / sizeof(entries[0]); ++index) {
        if (strcmp(entries[index].name, locale_id) == 0) return entries[index].value;
    }
    return 0;
}

typedef struct RinLocaleCode
{
    const char* id;
    const char* code;
} RinLocaleCode;

static const char* product_language_three_letter(const char* language)
{
    static const RinLocaleCode codes[] = {
        { "ar", "ara" }, { "cs", "ces" }, { "da", "dan" },
        { "de", "deu" }, { "en", "eng" }, { "es", "spa" },
        { "fa", "fas" }, { "he", "heb" },
        { "fi", "fin" }, { "fr", "fra" }, { "hi", "hin" },
        { "hu", "hun" }, { "id", "ind" }, { "it", "ita" },
        { "ja", "jpn" }, { "ko", "kor" }, { "nl", "nld" },
        { "pl", "pol" }, { "pt", "por" }, { "ro", "ron" },
        { "ru", "rus" }, { "sv", "swe" }, { "th", "tha" },
        { "tr", "tur" }, { "uk", "ukr" }, { "vi", "vie" },
        { "zh", "zho" }
    };
    size_t index;
    if (!language || language[0] == '\0') return NULL;
    for (index = 0u; index < sizeof(codes) / sizeof(codes[0]); ++index) {
        if (strcmp(codes[index].id, language) == 0) return codes[index].code;
    }
    return NULL;
}

static const char* product_region_three_letter(const char* region)
{
    static const RinLocaleCode codes[] = {
        { "BR", "BRA" }, { "CN", "CHN" }, { "CZ", "CZE" },
        { "DE", "DEU" }, { "DK", "DNK" }, { "ES", "ESP" },
        { "FI", "FIN" }, { "FR", "FRA" }, { "GB", "GBR" },
        { "HU", "HUN" }, { "ID", "IDN" }, { "IL", "ISR" }, { "IN", "IND" },
        { "IT", "ITA" }, { "JP", "JPN" }, { "KR", "KOR" },
        { "MX", "MEX" }, { "NL", "NLD" }, { "PL", "POL" },
        { "PT", "PRT" }, { "RO", "ROU" }, { "RU", "RUS" },
        { "IR", "IRN" },
        { "SA", "SAU" }, { "SE", "SWE" }, { "TH", "THA" },
        { "TR", "TUR" }, { "TW", "TWN" }, { "UA", "UKR" },
        { "US", "USA" }, { "VN", "VNM" }
    };
    size_t index;
    if (!region || region[0] == '\0') return NULL;
    for (index = 0u; index < sizeof(codes) / sizeof(codes[0]); ++index) {
        if (strcmp(codes[index].id, region) == 0) return codes[index].code;
    }
    return NULL;
}

/* LocaleString_Digits follows the ICU/.NET contract rather than returning a
 * display-ready number.  Each native digit is separated by U+FFFF so the
 * managed caller can preserve digits which occupy more than one UTF-16 code
 * unit.  The product catalog currently carries script, not a separate
 * numbering-system field, so scripts with an explicitly shipped digit set
 * select non-ASCII digits; fa-IR is additionally selected by language because
 * Persian digits differ from the Arabic script's default digits. */
static const char* product_native_digits(const RinIcuDataLocaleRecord* record)
{
    static const char ascii_digits[] =
        "0" "\xEF\xBF\xBF" "1" "\xEF\xBF\xBF" "2" "\xEF\xBF\xBF"
        "3" "\xEF\xBF\xBF" "4" "\xEF\xBF\xBF" "5" "\xEF\xBF\xBF"
        "6" "\xEF\xBF\xBF" "7" "\xEF\xBF\xBF" "8" "\xEF\xBF\xBF"
        "9";
    static const char arabic_digits[] =
        "٠" "\xEF\xBF\xBF" "١" "\xEF\xBF\xBF" "٢" "\xEF\xBF\xBF"
        "٣" "\xEF\xBF\xBF" "٤" "\xEF\xBF\xBF" "٥" "\xEF\xBF\xBF"
        "٦" "\xEF\xBF\xBF" "٧" "\xEF\xBF\xBF" "٨" "\xEF\xBF\xBF"
        "٩";
    static const char devanagari_digits[] =
        "०" "\xEF\xBF\xBF" "१" "\xEF\xBF\xBF" "२" "\xEF\xBF\xBF"
        "३" "\xEF\xBF\xBF" "४" "\xEF\xBF\xBF" "५" "\xEF\xBF\xBF"
        "६" "\xEF\xBF\xBF" "७" "\xEF\xBF\xBF" "८" "\xEF\xBF\xBF"
        "९";
    static const char persian_digits[] =
        "۰" "\xEF\xBF\xBF" "۱" "\xEF\xBF\xBF" "۲" "\xEF\xBF\xBF"
        "۳" "\xEF\xBF\xBF" "۴" "\xEF\xBF\xBF" "۵" "\xEF\xBF\xBF"
        "۶" "\xEF\xBF\xBF" "۷" "\xEF\xBF\xBF" "۸" "\xEF\xBF\xBF"
        "۹";
    static const char thai_digits[] =
        "๐" "\xEF\xBF\xBF" "๑" "\xEF\xBF\xBF" "๒" "\xEF\xBF\xBF"
        "๓" "\xEF\xBF\xBF" "๔" "\xEF\xBF\xBF" "๕" "\xEF\xBF\xBF"
        "๖" "\xEF\xBF\xBF" "๗" "\xEF\xBF\xBF" "๘" "\xEF\xBF\xBF"
        "๙";
    if (!record) return NULL;
    if (strcmp(record->language, "fa") == 0) return persian_digits;
    if (strcmp(record->script, "Arab") == 0) return arabic_digits;
    if (strcmp(record->script, "Deva") == 0) return devanagari_digits;
    if (strcmp(record->script, "Thai") == 0) return thai_digits;
    return ascii_digits;
}

static int product_pattern_order(const char* pattern, const char* first_token,
                                 const char* second_token, int* first_is_left,
                                 int* separated)
{
    const char* first;
    const char* second;
    const char* left;
    const char* left_token;
    const char* cursor;
    if (!pattern || !first_token || !second_token || !first_is_left || !separated) return 0;
    first = strstr(pattern, first_token);
    second = strstr(pattern, second_token);
    if (!first || !second || first == second) return 0;
    *first_is_left = first < second;
    left = *first_is_left ? first : second;
    left_token = *first_is_left ? first_token : second_token;
    cursor = left + strlen(left_token);
    second = *first_is_left ? second : first;
    *separated = 0;
    while (cursor < second) {
        if (*cursor == ' ') {
            *separated = 1;
            break;
        }
        ++cursor;
    }
    return 1;
}

static int product_currency_positive_pattern(const RinIcuDataLocaleRecord* record)
{
    int symbol_first;
    int separated;
    if (!record || !product_pattern_order(record->currency_pattern, "{symbol}",
                                          "{value}", &symbol_first, &separated)) return -1;
    if (symbol_first) return separated ? 2 : 0;
    return separated ? 3 : 1;
}

static int product_percent_positive_pattern(const RinIcuDataLocaleRecord* record)
{
    int percent_first;
    int separated;
    if (!record || !product_pattern_order(record->percent_pattern, "{percent}",
                                          "{value}", &percent_first, &separated)) return -1;
    if (percent_first) return separated ? 3 : 2;
    return separated ? 0 : 1;
}

static int product_first_day_of_week(const char* region)
{
    static const char* sunday_regions[] = {
        "BR", "CA", "ID", "IN", "JP", "KR", "MX", "PT", "SA", "TH", "TW", "US"
    };
    static const char* saturday_regions[] = {
        "IR"
    };
    size_t index;
    if (!region) return -1;
    if (region[0] == '\0') return 0;
    for (index = 0u; index < sizeof(sunday_regions) / sizeof(sunday_regions[0]); ++index) {
        if (strcmp(region, sunday_regions[index]) == 0) return 0;
    }
    for (index = 0u; index < sizeof(saturday_regions) / sizeof(saturday_regions[0]); ++index) {
        if (strcmp(region, saturday_regions[index]) == 0) return 6;
    }
    return 1;
}

static int product_first_week_rule(const char* region)
{
    static const char* first_four_day_regions[] = {
        "AT", "BE", "BG", "CH", "CZ", "DE", "DK", "EE", "ES", "FI", "FR", "GB",
        "GR", "IE", "IS", "IT", "LT", "LU", "NL", "PL", "PT", "RU", "SE", "SK"
    };
    size_t index;
    if (!region) return -1;
    if (region[0] == '\0') return 0;
    for (index = 0u; index < sizeof(first_four_day_regions) / sizeof(first_four_day_regions[0]); ++index) {
        if (strcmp(region, first_four_day_regions[index]) == 0) return 2;
    }
    return 0;
}

static size_t record_field_length(const char* field, size_t capacity)
{
    size_t length = 0u;
    if (!field) return 0u;
    while (length < capacity && field[length] != '\0') ++length;
    return length;
}

static int append_display_name_text(char* dest, size_t capacity, size_t* length, const char* text)
{
    size_t text_length;
    if (!dest || !length || !text || *length >= capacity) return 0;
    text_length = strlen(text);
    if (text_length >= capacity - *length) return 0;
    memcpy(dest + *length, text, text_length);
    *length += text_length;
    dest[*length] = '\0';
    return 1;
}

static int product_locale_display_name(rin_icu_client_t* client,
                                       const char* display_locale,
                                       const RinIcuDataLocaleRecord* record,
                                       char* dest,
                                       size_t capacity,
                                       size_t* out_length)
{
    char language[256];
    char region[256];
    size_t language_length = 0u;
    size_t region_length = 0u;
    size_t length = 0u;
    int status;
    if (!client || !display_locale || !record || !dest || capacity == 0u) return RIN_ICU_STATUS_INVALID;
    status = rin_icu_display_name(client, display_locale, record->language,
                                  RIN_ICU_DISPLAY_NAME_LANGUAGE, RIN_ICU_STYLE_LONG,
                                  RIN_ICU_LANGUAGE_DISPLAY_STANDARD, language,
                                  sizeof(language), &language_length);
    if (status != RIN_ICU_STATUS_OK || language_length >= sizeof(language) ||
        !append_display_name_text(dest, capacity, &length, language)) {
        return status != RIN_ICU_STATUS_OK ? status : RIN_ICU_STATUS_NO_SPACE;
    }
    if (record->region[0] != '\0') {
        status = rin_icu_display_name(client, display_locale, record->region,
                                      RIN_ICU_DISPLAY_NAME_REGION, RIN_ICU_STYLE_LONG,
                                      RIN_ICU_LANGUAGE_DISPLAY_STANDARD, region,
                                      sizeof(region), &region_length);
        if (status != RIN_ICU_STATUS_OK || region_length >= sizeof(region) ||
            !append_display_name_text(dest, capacity, &length, " (") ||
            !append_display_name_text(dest, capacity, &length, region) ||
            !append_display_name_text(dest, capacity, &length, ")")) {
            return status != RIN_ICU_STATUS_OK ? status : RIN_ICU_STATUS_NO_SPACE;
        }
    }
    if (out_length) *out_length = length;
    return RIN_ICU_STATUS_OK;
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

static int product_year_month_pattern(const char* source, size_t source_capacity,
                                      char* dest, size_t capacity)
{
    size_t length;
    size_t index;
    if (!source || !dest || capacity == 0u ||
        product_pattern(source, source_capacity, 0, 0, dest, capacity) <= 0) {
        return 0;
    }
    length = strlen(dest);
    for (index = 0u; index + 1u < length; ++index) {
        if (dest[index] != 'd' || dest[index + 1u] != 'd') continue;
        if (index > 0u && (dest[index - 1u] == '/' || dest[index - 1u] == '-' ||
                           dest[index - 1u] == '.')) {
            memmove(dest + index - 1u, dest + index + 2u,
                    length - (index + 1u));
            length -= 3u;
        } else if (index + 2u < length &&
                   (dest[index + 2u] == '/' || dest[index + 2u] == '-' ||
                    dest[index + 2u] == '.')) {
            memmove(dest + index, dest + index + 3u,
                    length - (index + 2u));
            length -= 3u;
        } else {
            memmove(dest + index, dest + index + 2u,
                    length - index - 1u);
            length -= 2u;
        }
        dest[length] = '\0';
        return length > 0u && strstr(dest, "yyyy") != NULL &&
               strstr(dest, "MM") != NULL ? (int)length : 0;
    }
    return 0;
}

static int service_text_call(int (*call)(rin_icu_client_t*, const char*, char*, size_t, size_t*),
                             const char* input, UChar* dest, int32_t capacity)
{
    rin_icu_client_t* client = product_client();
    char buffer[256];
    size_t length = 0u;
    char* dynamic = NULL;
    int status;
    if (!client) return -1;
    status = call(client, input ? input : "", buffer, sizeof(buffer), &length);
    if (status == RIN_ICU_STATUS_NO_SPACE) {
        if (length == SIZE_MAX || length > RIN_ICU_MAX_INLINE_PAYLOAD) return -1;
        dynamic = (char*)malloc(length + 1u);
        if (!dynamic) return -1;
        status = call(client, input ? input : "", dynamic, length + 1u, &length);
    }
    if (status != RIN_ICU_STATUS_OK || length > RIN_ICU_MAX_INLINE_PAYLOAD) {
        free(dynamic);
        return -1;
    }
    status = copy_utf8_z(dynamic ? dynamic : buffer, length, dest, capacity);
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
    if (!target || page_number < 0 || page_number > 0xff) return;
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
    if (!target || page_number < 0 || page_number > 0xff) return;
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
    size_t source_units_size = u16_length(source, source_length);
    int32_t source_units;
    if (length < 0) return 0;
    if (source_units_size == SIZE_MAX || source_units_size > (size_t)INT32_MAX) return 0;
    source_units = (int32_t)source_units_size;
    if (length >= INT32_MAX) return 0;
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

static void collator_options_from_compare(int32_t compare_options,
                                          rin_icu_collator_options_t* options)
{
    uint32_t normalized = (uint32_t)compare_options & CompareOptionsMask;
    memset(options, 0, sizeof(*options));
    options->strength = (normalized & CompareOptionsIgnoreNonSpace) != 0u
        ? RIN_ICU_COLLATION_STRENGTH_PRIMARY
        : (normalized & CompareOptionsIgnoreCase) != 0u
            ? RIN_ICU_COLLATION_STRENGTH_SECONDARY
            : RIN_ICU_COLLATION_STRENGTH_TERTIARY;
    options->numeric = (normalized & CompareOptionsNumericOrdering) != 0u;
    options->ignore_punctuation = (normalized & CompareOptionsIgnoreSymbols) != 0u;
    if ((normalized & CompareOptionsIgnoreKanaType) != 0u) {
        options->case_first |= RIN_ICU_COLLATOR_FLAG_IGNORE_KANA_TYPE;
    }
    if ((normalized & CompareOptionsIgnoreWidth) != 0u) {
        options->case_first |= RIN_ICU_COLLATOR_FLAG_IGNORE_WIDTH;
    }
}

static int create_sort_handle(const char* locale, SortHandle** out_handle)
{
    rin_icu_client_t* client = product_client();
    rin_icu_collator_options_t options = { 0 };
    SortHandle* result;
    const char* locale_name = locale ? locale : "root";
    if (!client || !out_handle) return 0;
    if (strlen(locale_name) >= sizeof(result->locale)) return 0;
    options.strength = RIN_ICU_COLLATION_STRENGTH_TERTIARY;
    result = (SortHandle*)calloc(1u, sizeof(SortHandle));
    if (!result) return 0;
    result->client = client;
    memcpy(result->locale, locale_name, strlen(locale_name) + 1u);
    if (rin_icu_collator_create(result->client, result->locale, &options, &result->handle) != RIN_ICU_STATUS_OK) {
        free(result);
        return 0;
    }
    result->option_handles[0] = result->handle;
    result->option_initialized[0] = 1u;
    *out_handle = result;
    return 1;
}

static rin_icu_handle_t collator_handle_for_options(SortHandle* handle, int32_t compare_options)
{
    uint32_t raw_options = (uint32_t)compare_options;
    uint32_t normalized;
    rin_icu_collator_options_t options;
    rin_icu_handle_t service_handle = 0u;
    if (!handle || (raw_options & ~((uint32_t)CompareOptionsMask)) != 0u) return 0u;
    normalized = raw_options & CompareOptionsMask;
    if (handle->option_initialized[normalized]) return handle->option_handles[normalized];
    collator_options_from_compare(compare_options, &options);
    if (rin_icu_collator_create(handle->client, handle->locale, &options, &service_handle) != RIN_ICU_STATUS_OK) {
        return 0u;
    }
    handle->option_handles[normalized] = service_handle;
    handle->option_initialized[normalized] = 1u;
    return service_handle;
}

int32_t GlobalizationNative_GetSortHandle(const char* locale, SortHandle** out_handle)
{
    return create_sort_handle(locale, out_handle) ? Success : UnknownError;
}

void GlobalizationNative_CloseSortHandle(SortHandle* handle)
{
    uint32_t option;
    if (!handle) return;
    for (option = 0u; option < CompareOptionsMask + 1u; ++option) {
        if (handle->option_initialized[option]) {
            (void)rin_icu_collator_destroy(handle->client, handle->option_handles[option]);
        }
    }
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
    int result = -1;
    rin_icu_handle_t service_handle = collator_handle_for_options(handle, options);
    if (!handle || !left || !right || service_handle == 0u ||
        rin_icu_collator_compare(handle->client, service_handle, left, right, &result) != RIN_ICU_STATUS_OK) result = -1;
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
    rin_icu_handle_t service_handle = collator_handle_for_options(handle, options);
    if (!handle || !input || dest_length < 0) {
        free(input);
        return 0;
    }
    if (service_handle == 0u) {
        free(input);
        return 0;
    }
    status = rin_icu_collator_sort_key(handle->client, service_handle, input, buffer, sizeof(buffer), &output_length);
    if (status == RIN_ICU_STATUS_NO_SPACE) {
        if (output_length == SIZE_MAX || output_length > RIN_ICU_MAX_INLINE_PAYLOAD) {
            status = RIN_ICU_STATUS_DATA_ERROR;
        } else {
            output = (uint8_t*)malloc(output_length + 1u);
            if (output) status = rin_icu_collator_sort_key(handle->client, service_handle, input, output, output_length + 1u, &output_length);
        }
    }
    if (status != RIN_ICU_STATUS_OK || output_length > (size_t)INT32_MAX) output_length = 0u;
    if (dest && dest_length > 0 && output_length > 0u) {
        size_t copy_length = output_length < (size_t)dest_length ? output_length : (size_t)dest_length;
        memcpy(dest, output, copy_length);
    }
    free(output == buffer ? NULL : output);
    free(input);
    return (int32_t)output_length;
}

static int compare_slice(SortHandle* handle, const UChar* source, int32_t source_length, int32_t offset, const UChar* target, int32_t target_length, int32_t options)
{
    char* left;
    char* right;
    int result = 0;
    rin_icu_handle_t service_handle;

    if (!handle || !source || !target || source_length < 0 || offset < 0 || target_length < 0 ||
        (size_t)offset > (size_t)source_length ||
        (size_t)target_length > (size_t)source_length - (size_t)offset) {
        return 0;
    }

    left = sort_text(source + offset, target_length, NULL);
    right = sort_text(target, target_length, NULL);
    service_handle = collator_handle_for_options(handle, options);
    if (!left || !right || service_handle == 0u ||
        rin_icu_collator_compare(handle->client, service_handle, left, right, &result) != RIN_ICU_STATUS_OK) result = 1;
    free(left);
    free(right);
    return result == 0;
}

int32_t GlobalizationNative_IndexOf(SortHandle* handle, const UChar* target, int32_t target_length, const UChar* source, int32_t source_length, int32_t options, int32_t* matched_length)
{
    int32_t i;
    if (matched_length) *matched_length = 0;
    if (!handle || !target || !source || target_length < 0 || source_length < 0) return -1;
    if (target_length > source_length) return -1;
    for (i = 0; i <= source_length - target_length; ++i) {
        if (compare_slice(handle, source, source_length, i, target, target_length, options)) {
            if (matched_length) *matched_length = target_length;
            return i;
        }
    }
    return -1;
}

int32_t GlobalizationNative_LastIndexOf(SortHandle* handle, const UChar* target, int32_t target_length, const UChar* source, int32_t source_length, int32_t options, int32_t* matched_length)
{
    int32_t i;
    if (matched_length) *matched_length = 0;
    if (!handle || !target || !source || target_length < 0 || source_length < 0) return -1;
    for (i = source_length - target_length; i >= 0; --i) {
        if (compare_slice(handle, source, source_length, i, target, target_length, options)) {
            if (matched_length) *matched_length = target_length;
            return i;
        }
    }
    return -1;
}

int32_t GlobalizationNative_StartsWith(SortHandle* handle, const UChar* target, int32_t target_length, const UChar* source, int32_t source_length, int32_t options, int32_t* matched_length)
{
    if (matched_length) *matched_length = 0;
    if (!handle || target_length < 0 || source_length < target_length) return 0;
    if (!compare_slice(handle, source, source_length, 0, target, target_length, options)) return 0;
    if (matched_length) *matched_length = target_length;
    return 1;
}

int32_t GlobalizationNative_EndsWith(SortHandle* handle, const UChar* target, int32_t target_length, const UChar* source, int32_t source_length, int32_t options, int32_t* matched_length)
{
    if (matched_length) *matched_length = 0;
    if (!handle || target_length < 0 || source_length < target_length) return 0;
    if (!compare_slice(handle, source, source_length, source_length - target_length, target, target_length, options)) return 0;
    if (matched_length) *matched_length = target_length;
    return 1;
}

static int32_t locale_call(const UChar* locale, UChar* value, int32_t value_length, int (*call)(rin_icu_client_t*, const char*, char*, size_t, size_t*))
{
    char* locale_name = locale_utf8(locale);
    int32_t result;
    if (!locale_name) return 0;
    result = service_text_call(call, locale_name, value, value_length);
    free(locale_name);
    return result;
}

int32_t GlobalizationNative_GetLocaleName(const UChar* locale, UChar* value, int32_t value_length)
{
    return locale_call(locale, value, value_length, rin_icu_locale_canonicalize) >= 0;
}

int32_t GlobalizationNative_GetDefaultLocaleName(UChar* value, int32_t value_length)
{
    rin_icu_client_t* client = product_client();
    char buffer[128];
    size_t length = 0u;
    if (!client || rin_icu_locale_preferred(client, buffer, sizeof(buffer), &length) != RIN_ICU_STATUS_OK) return 0;
    return copy_utf8_z(buffer, length, value, value_length) >= 0;
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
    if (!client || value_length < 0) return -1;
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
        char* zone = strstr(format, " Z");
        if (seconds) memmove(seconds, seconds + 3u, strlen(seconds + 3u) + 1u);
        if (zone) memmove(zone, zone + 2u, strlen(zone + 2u) + 1u);
    }
    result = copy_utf8_z(format, strlen(format), value, value_length);
    return result >= 0;
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
        /* ICU represents the parent of a neutral locale and of the root
         * locale as the invariant culture, which is the empty locale name.
         * Returning the product-internal "root" identifier leaks the service
         * catalog key through CultureInfo.Parent. */
        if (capacity == 0u) return 0;
        parent[0] = '\0';
        return 1;
    }
    length = (size_t)(separator - canonical);
    if (length == 0u || length >= capacity) return 0;
    memcpy(parent, canonical, length);
    parent[length] = '\0';
    return 1;
}

static int locale_string_requires_ui_locale(LocaleStringData kind)
{
    return kind == LocaleString_LocalizedDisplayName ||
        kind == LocaleString_LocalizedLanguageName;
}

int32_t GlobalizationNative_GetLocaleInfoString(const UChar* locale, LocaleStringData kind, UChar* value, int32_t value_length, const UChar* ui_locale)
{
    char* locale_name = locale_utf8(locale);
    char* ui_name = NULL;
    RinIcuDataLocaleRecord record;
    char buffer[256];
    char parent[128];
    const char* field = NULL;
    size_t field_capacity = 0u;
    size_t length = 0u;
    int status = RIN_ICU_STATUS_UNSUPPORTED;
    rin_icu_client_t* client = product_client();
    int have_record;
    if (!locale_name) {
        return 0;
    }
    if (locale_string_requires_ui_locale(kind) && !ui_locale) {
        free(locale_name);
        return 0;
    }
    if (locale_string_requires_ui_locale(kind)) {
        ui_name = locale_utf8(ui_locale);
        if (!ui_name) {
            free(locale_name);
            return 0;
        }
    }
    have_record = get_locale_record(locale, &record);
    if (client && have_record && (kind == LocaleString_EnglishDisplayName || kind == LocaleString_NativeDisplayName || kind == LocaleString_LocalizedDisplayName ||
                                  kind == LocaleString_EnglishLanguageName || kind == LocaleString_NativeLanguageName || kind == LocaleString_LocalizedLanguageName ||
                                  kind == LocaleString_EnglishCountryName || kind == LocaleString_NativeCountryName ||
                                  kind == LocaleString_CurrencyEnglishName || kind == LocaleString_CurrencyNativeName)) {
        uint32_t type = RIN_ICU_DISPLAY_NAME_LANGUAGE;
        const char* code = locale_name;
        uint32_t style = RIN_ICU_STYLE_LONG;
        int locale_display_name = kind == LocaleString_EnglishDisplayName ||
            kind == LocaleString_NativeDisplayName || kind == LocaleString_LocalizedDisplayName;
        const char* display_locale = ui_name;
        if (locale_display_name) code = record.language;
        if (kind == LocaleString_EnglishCountryName || kind == LocaleString_NativeCountryName) {
            type = RIN_ICU_DISPLAY_NAME_REGION;
            code = record.region;
        } else if (kind == LocaleString_CurrencyEnglishName || kind == LocaleString_CurrencyNativeName) {
            type = RIN_ICU_DISPLAY_NAME_CURRENCY;
            code = record.currency_code;
        } else if (kind == LocaleString_EnglishLanguageName || kind == LocaleString_NativeLanguageName || kind == LocaleString_LocalizedLanguageName) {
            code = record.language;
        }
        if (kind == LocaleString_EnglishDisplayName || kind == LocaleString_EnglishLanguageName ||
            kind == LocaleString_EnglishCountryName || kind == LocaleString_CurrencyEnglishName) {
            display_locale = "en";
        } else if (kind == LocaleString_NativeDisplayName || kind == LocaleString_NativeLanguageName ||
                   kind == LocaleString_NativeCountryName || kind == LocaleString_CurrencyNativeName) {
            display_locale = locale_name;
        }
        status = locale_display_name
            ? product_locale_display_name(client, display_locale, &record, buffer, sizeof(buffer), &length)
            : rin_icu_display_name(client, display_locale, code, type, style, RIN_ICU_LANGUAGE_DISPLAY_STANDARD, buffer, sizeof(buffer), &length);
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
            case LocaleString_Iso639LanguageThreeLetterName:
                field = product_language_three_letter(record.language);
                field_capacity = field ? strlen(field) + 1u : 0u;
                break;
            case LocaleString_Iso3166CountryName: field = record.region; field_capacity = sizeof(record.region); break;
            case LocaleString_Iso3166CountryName2:
                field = product_region_three_letter(record.region);
                field_capacity = field ? strlen(field) + 1u : 0u;
                break;
            case LocaleString_ParentName:
                if (locale_parent_name(client, locale_name, parent, sizeof(parent))) {
                    field = parent;
                    field_capacity = sizeof(parent);
                }
                break;
            case LocaleString_Digits:
                field = product_native_digits(&record);
                field_capacity = field ? strlen(field) + 1u : 0u;
                break;
            case LocaleString_NaNSymbol: field = "NaN"; field_capacity = sizeof("NaN"); break;
            case LocaleString_PositiveInfinitySymbol: field = "Infinity"; field_capacity = sizeof("Infinity"); break;
            case LocaleString_NegativeInfinitySymbol: field = "-Infinity"; field_capacity = sizeof("-Infinity"); break;
            case LocaleString_PerMilleSymbol: field = "‰"; field_capacity = sizeof("‰"); break;
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
    return copy_utf8_z(buffer, length, value, value_length) >= 0;
}

int32_t GlobalizationNative_GetLocaleInfoInt(const UChar* locale, LocaleNumberData kind, int32_t* value)
{
    RinIcuDataLocaleRecord record;
    int pattern;
    int have_record = get_locale_record(locale, &record);
    if (!value) return 0;
    if (!have_record) return 0;
    switch (kind) {
        case LocaleNumber_LanguageId:
            *value = product_locale_language_id(record.locale_id);
            return *value != 0 || strcmp(record.locale_id, "root") == 0;
        case LocaleNumber_MeasurementSystem:
            *value = (strcmp(record.region, "US") == 0 || strcmp(record.region, "LR") == 0 || strcmp(record.region, "MM") == 0) ? 1 : 0;
            break;
        case LocaleNumber_FirstDayofWeek:
            *value = product_first_day_of_week(record.region);
            if (*value < 0) return 0;
            break;
        case LocaleNumber_FractionalDigitsCount:
            /* The product catalog uses the .NET/CLDR default of two decimal
             * digits for ordinary numbers.  Currency precision is carried
             * separately in currency_digits below. */
            *value = 2;
            break;
        case LocaleNumber_MonetaryFractionalDigitsCount:
            *value = (int32_t)record.currency_digits;
            break;
        case LocaleNumber_NegativeNumberFormat:
            *value = 1;
            break;
        case LocaleNumber_PositiveMonetaryNumberFormat:
            pattern = product_currency_positive_pattern(&record);
            if (pattern < 0 && strcmp(record.locale_id, "root") == 0) pattern = 0;
            if (pattern < 0) return 0;
            *value = pattern;
            break;
        case LocaleNumber_NegativeMonetaryNumberFormat:
            pattern = product_currency_positive_pattern(&record);
            if (pattern < 0 && strcmp(record.locale_id, "root") == 0) pattern = 0;
            if (pattern < 0) return 0;
            if (pattern == 0) {
                *value = strcmp(record.region, "US") == 0 ? 0 : 1;
            } else if (pattern == 1) {
                *value = 5;
            } else if (pattern == 2) {
                *value = 9;
            } else {
                *value = 8;
            }
            break;
        case LocaleNumber_FirstWeekOfYear:
            *value = product_first_week_rule(record.region);
            if (*value < 0) return 0;
            break;
        case LocaleNumber_ReadingLayout:
            *value = strcmp(record.script, "Arab") == 0 ||
                strcmp(record.language, "fa") == 0 ||
                strcmp(record.language, "he") == 0 ||
                strcmp(record.language, "ur") == 0;
            break;
        case LocaleNumber_NegativePercentFormat:
            pattern = product_percent_positive_pattern(&record);
            if (pattern < 0) return 0;
            *value = pattern == 0 ? 0 : pattern == 1 ? 1 : pattern == 2 ? 2 : 7;
            break;
        case LocaleNumber_PositivePercentFormat:
            pattern = product_percent_positive_pattern(&record);
            if (pattern < 0) return 0;
            *value = pattern;
            break;
        case LocaleNumber_Digit:
            return 0;
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
    *secondary = strcmp(record.region, "IN") == 0 && *primary != 0 ? 2 : *primary;
    return 1;
}

int32_t GlobalizationNative_GetCalendars(const UChar* locale, CalendarId* calendars, int32_t capacity)
{
    RinIcuDataLocaleRecord record;
    if (!calendars || capacity <= 0 || !get_locale_record(locale, &record)) return 0;
    if (strcmp(record.language, "fa") == 0 && strcmp(record.region, "IR") == 0) {
        calendars[0] = 22;
        if (capacity > 1) {
            calendars[1] = 1;
            return 2;
        }
        return 1;
    }
    if (strcmp(record.language, "ar") == 0 && strcmp(record.region, "SA") == 0) {
        calendars[0] = 23;
        if (capacity > 1) {
            calendars[1] = 1;
            return 2;
        }
        return 1;
    }
    calendars[0] = 1;
    if (capacity > 1) {
        if (strcmp(record.language, "ja") == 0) {
            calendars[1] = 3;
            return 2;
        }
        if (strcmp(record.language, "th") == 0 &&
            strcmp(record.region, "TH") == 0) {
            calendars[1] = 7;
            return 2;
        }
        if (strcmp(record.language, "zh") == 0 &&
            strcmp(record.region, "TW") == 0) {
            calendars[1] = 4;
            return 2;
        }
        if (strcmp(record.language, "ko") == 0 &&
            strcmp(record.region, "KR") == 0) {
            calendars[1] = 5;
            return 2;
        }
        if (strcmp(record.language, "he") == 0 &&
            strcmp(record.region, "IL") == 0) {
            calendars[1] = 8;
            return 2;
        }
    }
    return 1;
}

ResultCode GlobalizationNative_GetCalendarInfo(const UChar* locale, CalendarId calendar, CalendarDataType kind, UChar* value, int32_t capacity)
{
    RinIcuDataLocaleRecord record;
    char pattern[128];
    const char* date_pattern;
    size_t date_pattern_capacity;
    if (capacity < 0 || !get_locale_record(locale, &record) ||
        !is_product_calendar_for_locale(&record, calendar)) return UnknownError;
    switch (kind) {
        case CalendarData_NativeName:
            return copy_calendar_text(calendar_symbol(&record, calendar, kind, 0u), value, capacity, NULL);
        case CalendarData_MonthDay:
        case CalendarData_ShortDates:
        case CalendarData_LongDates:
            date_pattern = kind == CalendarData_LongDates ? record.long_date_pattern : record.date_pattern;
            date_pattern_capacity = kind == CalendarData_LongDates
                ? sizeof(record.long_date_pattern) : sizeof(record.date_pattern);
            if (!product_pattern(date_pattern, date_pattern_capacity, 0, kind == CalendarData_MonthDay, pattern, sizeof(pattern))) return UnknownError;
            return copy_calendar_text(pattern, value, capacity, NULL);
        case CalendarData_YearMonths:
            if (!product_year_month_pattern(record.date_pattern, sizeof(record.date_pattern), pattern, sizeof(pattern))) return UnknownError;
            return copy_calendar_text(pattern, value, capacity, NULL);
        default:
            return UnknownError;
    }
}

int32_t GlobalizationNative_EnumCalendarInfo(EnumCalendarInfoCallback callback, const UChar* locale, CalendarId calendar, CalendarDataType kind, const void* context)
{
    RinIcuDataLocaleRecord record;
    UChar pattern[128];
    int32_t pattern_length;
    if (!callback || !get_locale_record(locale, &record) ||
        !is_product_calendar_for_locale(&record, calendar)) return 0;
    if (kind == CalendarData_NativeName) {
        UChar name[64];
        int32_t length = 0;
        if (copy_calendar_text(calendar_symbol(&record, calendar, kind, 0u), name,
                               (int32_t)(sizeof(name) / sizeof(name[0])) - 1, &length) != Success) return 0;
        name[length] = 0;
        callback(name, context);
        return 1;
    }
    if (calendar_symbol_count(calendar, kind) != 0u) {
        size_t index;
        size_t count = calendar_symbol_count(calendar, kind);
        for (index = 0u; index < count; ++index) {
            UChar symbol[64];
            int32_t length = 0;
            if (copy_calendar_text(calendar_symbol(&record, calendar, kind, index), symbol,
                                   (int32_t)(sizeof(symbol) / sizeof(symbol[0])) - 1, &length) != Success) return 0;
            symbol[length] = 0;
            callback(symbol, context);
        }
        return (int32_t)count;
    }
    if (kind != CalendarData_ShortDates && kind != CalendarData_LongDates &&
        kind != CalendarData_YearMonths) return 0;
    {
        char product_format[128];
        const char* date_pattern = kind == CalendarData_LongDates
            ? record.long_date_pattern : record.date_pattern;
        size_t date_pattern_capacity = kind == CalendarData_LongDates
            ? sizeof(record.long_date_pattern) : sizeof(record.date_pattern);
        int format_length = kind == CalendarData_YearMonths
            ? product_year_month_pattern(record.date_pattern, sizeof(record.date_pattern), product_format, sizeof(product_format))
            : product_pattern(date_pattern, date_pattern_capacity, 0, 0, product_format, sizeof(product_format));
        if (format_length <= 0) return 0;
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
    { "Eastern Standard Time", "America/Toronto", "CA" },
    { "Central Standard Time", "America/Chicago", "US" },
    { "Mountain Standard Time", "America/Denver", "US" },
    { "Pacific Standard Time", "America/Los_Angeles", "US" },
    { "US Mountain Standard Time", "America/Phoenix", "US" },
    { "Central Standard Time (Mexico)", "America/Mexico_City", "MX" },
    { "E. South America Standard Time", "America/Sao_Paulo", "BR" },
    { "Argentina Standard Time", "America/Buenos_Aires", "AR" },
    { "GMT Standard Time", "Europe/London", "GB" },
    { "W. Europe Standard Time", "Europe/Berlin", "DE" },
    { "W. Europe Standard Time", "Europe/Rome", "IT" },
    { "Romance Standard Time", "Europe/Paris", "FR" },
    { "Romance Standard Time", "Europe/Madrid", "ES" },
    { "Central European Standard Time", "Europe/Warsaw", "PL" },
    { "FLE Standard Time", "Europe/Helsinki", "FI" },
    { "Russian Standard Time", "Europe/Moscow", "RU" },
    { "Tokyo Standard Time", "Asia/Tokyo", "JP" },
    { "Korea Standard Time", "Asia/Seoul", "KR" },
    { "China Standard Time", "Asia/Shanghai", "CN" },
    { "Taipei Standard Time", "Asia/Taipei", "TW" },
    { "Singapore Standard Time", "Asia/Singapore", "SG" },
    { "SE Asia Standard Time", "Asia/Bangkok", "TH" },
    { "India Standard Time", "Asia/Kolkata", "IN" },
    { "Arabian Standard Time", "Asia/Dubai", "AE" },
    { "AUS Eastern Standard Time", "Australia/Sydney", "AU" },
    { "AUS Eastern Standard Time", "Australia/Melbourne", "AU" },
    { "W. Australia Standard Time", "Australia/Perth", "AU" },
    { "New Zealand Standard Time", "Pacific/Auckland", "NZ" },
    { "Hong Kong Standard Time", "Asia/Hong_Kong", "HK" },
    { "UTC", "Etc/UTC", "001" },
    { "UTC", "UTC", "001" },
    { "UTC", "Etc/GMT", "001" },
    { "UTC", "GMT", "001" },
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
    RIN_IDNA_INITIAL_N = 128,
    RIN_IDNA_ALLOW_UNASSIGNED = 0x1,
    RIN_IDNA_USE_STD3_ASCII_RULES = 0x2,
    RIN_IDNA_FLAGS_MASK = RIN_IDNA_ALLOW_UNASSIGNED | RIN_IDNA_USE_STD3_ASCII_RULES
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

static int idna_ascii_label_valid(const char* label, size_t length, int use_std3)
{
    size_t index;
    if (!label || length == 0u || length > RIN_IDNA_MAX_LABEL ||
        label[0] == '-' || label[length - 1u] == '-') return 0;
    for (index = 0u; index < length; ++index) {
        char value = label[index];
        unsigned char byte = (unsigned char)value;
        if (byte <= 0x1fu || byte == 0x7fu) return 0;
        if (use_std3 && !((value >= 'a' && value <= 'z') ||
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
    folded[folded_length] = '\0';
    free(normalized);
    free(input);
    return folded;
}

static int idna_to_ascii_utf8(const char* source, size_t source_length, uint32_t flags,
                              char* output, size_t output_capacity,
                              size_t* output_length)
{
    char* normalized = idna_normalize_casefold(source, source_length);
    size_t source_offset = 0u;
    size_t output_offset = 0u;
    int use_std3 = (flags & RIN_IDNA_USE_STD3_ASCII_RULES) != 0u;
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
            if (!idna_ascii_label_valid(ascii_label, codepoint_count, use_std3)) {
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

static int idna_to_unicode_utf8(const char* source, size_t source_length, uint32_t flags,
                                char* output, size_t output_capacity,
                                size_t* output_length)
{
    size_t source_offset = 0u;
    size_t output_offset = 0u;
    int use_std3 = (flags & RIN_IDNA_USE_STD3_ASCII_RULES) != 0u;
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
            if (!idna_ascii_label_valid(source + label_start, label_end - label_start, use_std3)) return 0;
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
    if (dest && dest_length < 0) return 0;
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
    if ((flags & ~RIN_IDNA_FLAGS_MASK) != 0u) return 0;
    input = utf16_to_utf8(source, source_length, &input_length);
    if (!input || !idna_to_ascii_utf8(input, input_length, flags, output, sizeof(output), &output_length)) {
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
    if ((flags & ~RIN_IDNA_FLAGS_MASK) != 0u) return 0;
    input = utf16_to_utf8(source, source_length, &input_length);
    if (!input || !idna_to_unicode_utf8(input, input_length, flags, output, sizeof(output), &output_length)) {
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
        return -1;
    }
    status = rin_icu_display_name(client, locale_name, time_zone_name,
                                  service_type, style,
                                  RIN_ICU_LANGUAGE_DISPLAY_STANDARD,
                                  buffer, sizeof(buffer), &length);
    if (status == RIN_ICU_STATUS_NO_SPACE) {
        if (length == SIZE_MAX || length > RIN_ICU_MAX_INLINE_PAYLOAD) {
            free(locale_name);
            free(time_zone_name);
            return -1;
        }
        dynamic = (char*)malloc(length + 1u);
        if (!dynamic) {
            free(locale_name);
            free(time_zone_name);
            return -1;
        }
        status = rin_icu_display_name(client, locale_name, time_zone_name,
                                      service_type, style,
                                      RIN_ICU_LANGUAGE_DISPLAY_STANDARD,
                                      dynamic, length + 1u, &length);
    }
    free(locale_name);
    free(time_zone_name);
    if (status != RIN_ICU_STATUS_OK || length == 0u || length > RIN_ICU_MAX_INLINE_PAYLOAD) {
        free(dynamic);
        return -1;
    }
    status = copy_utf8_z(dynamic ? dynamic : buffer, length, dest, dest_length);
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
    if (length == SIZE_MAX) return 0;
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
    if (length == SIZE_MAX) return 0;
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
    if (required < 0) return UnknownError;
    if (result && result_length <= required) return InsufficientBuffer;
    if (result && timezone_display_name_call(locale, time_zone, type, result, result_length) < 0) return UnknownError;
    return Success;
}
