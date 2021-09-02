#ifndef __TIMEZONE_TABLE_H__
#define __TIMEZONE_TABLE_H__

#define ZONE_NAME_LEN           64

struct tz_table
{
    int     posix_offset;
    char    zonename[ZONE_NAME_LEN];
};

const struct tz_table timezone_table[] =
{
    {  12, "(GMT-12:00)Eniwetok, Kwajalein" },
    {  11, "(GMT-11:00)Midway Island, Samoa" },
    {  10, "(GMT-10:00)Hawaii" },
    {   9, "(GMT-09:00)Alaska" },
    {   8, "(GMT-08:00)Pacific Time (US & Canada); Tijuana" },
    {   7, "(GMT-07:00)Arizona" },
    {   7, "(GMT-07:00)Mountain Time (US & Canada)" },
    {   6, "(GMT-06:00)Central Time (US & Canada)" },
    {   6, "(GMT-06:00)Mexico City, Tegucigalpa" },
    {   6, "(GMT-06:00)Saskatchewan" },
    {   5, "(GMT-05:00)Bogota, Lima, Quito" },
    {   5, "(GMT-05:00)Eastern Time (US & Canada)" },
    {   5, "(GMT-05:00)Indiana (East)" },
    {   4, "(GMT-04:00)Atlantic Time (Canada)" },
    {   4, "(GMT-04:00)Caracas, La Paz" },
    {   4, "(GMT-04:00)Santiago" },
    {   3, "(GMT-03:30)Newfoundland" },
    {   3, "(GMT-03:00)Brasilia" },
    {   3, "(GMT-03:00)Buenos Aires, Georgetown" },
    {   2, "(GMT-02:00)Mid-Atlantic" },
    {   1, "(GMT-01:00)Azores, Cape Verde Is." },
    {   0, "(GMT)Casablanca, Monrovia" },
    {   0, "(GMT)Greenwich Mean Time: Dublin, Edinburgh, Lisbon, London" },
    {  -1, "(GMT+01:00)Amsterdam, Berlin, Bern, Rome, Stockholm, Vienna" },
    {  -1, "(GMT+01:00)Belgrade, Bratislava, Budapest, Ljubljana, Prague" },
    {  -1, "(GMT+01:00)Brussels, Copenhagen, Madrid, Paris, Vilnius" },
    {  -1, "(GMT+01:00)Sarajevo, Skopje, Warsaw, Zagreb" },
    {  -2, "(GMT+02:00)Athens, Istanbul, Minsk, Sofija" },
    {  -2, "(GMT+02:00)Bucharest" },
    {  -2, "(GMT+02:00)Cairo" },
    {  -2, "(GMT+02:00)Harare, Pretoria" },
    {  -2, "(GMT+02:00)Helsinki, Riga, Tallinn" },
    {  -2, "(GMT+02:00)Jerusalem" },
    {  -3, "(GMT+03:00)Baghdad, Kuwait, Riyadh" },
    {  -3, "(GMT+03:00)Moscow, St. Petersburg, Volgograd" },
    {  -3, "(GMT+03:00)Mairobi" },
    {  -3, "(GMT+03:30)Tehran" },
    {  -4, "(GMT+04:00)Abu Dhabi, Muscat" },
    {  -4, "(GMT+04:00)Baku, Tbilisi" },
    {  -4, "(GMT+04:30)Kabul" },
    {  -5, "(GMT+05:00)Ekaterinburg" },
    {  -5, "(GMT+05:00)Islamabad, Karachi, Tashkent" },
    {  -5, "(GMT+05:30)Bombay, Calcutta, Madras, New Delhi" },
    {  -6, "(GMT+06:00)Astana, Almaty, Dhaka" },
    {  -6, "(GMT+06:00)Colombo" },
    {  -7, "(GMT+07:00)Bangkok, Hanoi, Jakarta" },
    {  -8, "(GMT+08:00)Beijing, Chongqing, Hong Kong, Urumqi" },
    {  -8, "(GMT+08:00)Perth" },
    {  -8, "(GMT+08:00)Singapore" },
    {  -8, "(GMT+08:00)Taipei" },
    {  -9, "(GMT+09:00)Osaka, Sapporo, Tokyo" },
    {  -9, "(GMT+09:00)Seoul" },
    {  -9, "(GMT+09:00)Yakutsk" },
    {  -9, "(GMT+09:30)Adelaide" },
    {  -9, "(GMT+09:30)Darwin" },
    { -10, "(GMT+10:00)Brisbane" },
    { -10, "(GMT+10:00)Canberra, Melbourne, Sydney" },
    { -10, "(GMT+10:00)Guam, Port Moresby" },
    { -10, "(GMT+10:00)Hobart" },
    { -10, "(GMT+10:00)Vladivostok" },
    { -11, "(GMT+11:00)Magadan, Solomon Is., New Caledonia" },
    { -12, "(GMT+12:00)Auckland, Wllington" },
    { -12, "(GMT+12:00)Fiji, Kamchatka, Marshall Is." }
};

#define ZONE_NAME(_i)           timezone_table[_i].zonename

#define TIMEZONE_MAX_ENTRIES    (sizeof(timezone_table)/sizeof(struct tz_table))
#endif //__TIMEZONE_TABLE_H__
