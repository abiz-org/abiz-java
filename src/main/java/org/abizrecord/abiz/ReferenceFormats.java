package org.abizrecord.abiz;

import com.networknt.schema.ExecutionContext;
import com.networknt.schema.format.Format;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The five formats the record schema uses (email, hostname, date, date-time, uri), asserted with
 * exactly the definitions of the reference resolver's validator, {@code @cfworker/json-schema}
 * 4.1.1 ({@code format.js}, MIT licence), so that a record is accepted or refused the same way.
 * networknt's own definitions differ: for example its email format refuses the {@code .example}
 * documentation domain and its hostname format refuses a trailing dot.
 */
final class ReferenceFormats {
  private ReferenceFormats() {}

  private static final Pattern DATE = Pattern.compile("^(\\d\\d\\d\\d)-(\\d\\d)-(\\d\\d)\\z");
  private static final int[] DAYS = {0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
  private static final Pattern TIME =
      Pattern.compile("^(\\d\\d):(\\d\\d):(\\d\\d)(\\.\\d+)?(z|[+-]\\d\\d(?::?\\d\\d)?)?\\z", Pattern.CASE_INSENSITIVE);
  private static final Pattern DATE_TIME_SEPARATOR = Pattern.compile("t|" + Text.JS_SPACE, Pattern.CASE_INSENSITIVE);
  private static final Pattern HOSTNAME = Pattern.compile(
          "^(?=.{1,253}\\.?\\z)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\\.[a-z0-9](?:[-0-9a-z]{0,61}[0-9a-z])?)*\\.?\\z", Pattern.CASE_INSENSITIVE);
  private static final Pattern NOT_URI_FRAGMENT = Pattern.compile("/|:");
  private static final Pattern URI_PATTERN = Pattern.compile(
          "^(?:[a-z][a-z0-9+\\-.]*:)(?:\\/?\\/(?:(?:[a-z0-9\\-._~!$&'()*+,;=:]|%[0-9a-f]{2})*@)?(?:\\[(?:(?:(?:(?:[0-9a-f]{1,4}:){6}|::(?:[0-9a-f]{1,4}:){5}|(?:[0-9a-f]{1,4})?::(?:[0-9a-f]{1,4}:){4}|(?:(?:[0-9a-f]{1,4}:){0,1}[0-9a-f]{1,4})?::(?:[0-9a-f]{1,4}:){3}|(?:(?:[0-9a-f]{1,4}:){0,2}[0-9a-f]{1,4})?::(?:[0-9a-f]{1,4}:){2}|(?:(?:[0-9a-f]{1,4}:){0,3}[0-9a-f]{1,4})?::[0-9a-f]{1,4}:|(?:(?:[0-9a-f]{1,4}:){0,4}[0-9a-f]{1,4})?::)(?:[0-9a-f]{1,4}:[0-9a-f]{1,4}|(?:(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?))|(?:(?:[0-9a-f]{1,4}:){0,5}[0-9a-f]{1,4})?::[0-9a-f]{1,4}|(?:(?:[0-9a-f]{1,4}:){0,6}[0-9a-f]{1,4})?::)|[Vv][0-9a-f]+\\.[a-z0-9\\-._~!$&'()*+,;=:]+)\\]|(?:(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)|(?:[a-z0-9\\-._~!$&'()*+,;=]|%[0-9a-f]{2})*)(?::\\d*)?(?:\\/(?:[a-z0-9\\-._~!$&'()*+,;=:@]|%[0-9a-f]{2})*)*|\\/(?:(?:[a-z0-9\\-._~!$&'()*+,;=:@]|%[0-9a-f]{2})+(?:\\/(?:[a-z0-9\\-._~!$&'()*+,;=:@]|%[0-9a-f]{2})*)*)?|(?:[a-z0-9\\-._~!$&'()*+,;=:@]|%[0-9a-f]{2})+(?:\\/(?:[a-z0-9\\-._~!$&'()*+,;=:@]|%[0-9a-f]{2})*)*)(?:\\?(?:[a-z0-9\\-._~!$&'()*+,;=:@/?]|%[0-9a-f]{2})*)?(?:#(?:[a-z0-9\\-._~!$&'()*+,;=:@/?]|%[0-9a-f]{2})*)?\\z", Pattern.CASE_INSENSITIVE);
  private static final Pattern EMAIL_HOST = Pattern.compile("^[a-z0-9.-]+\\z", Pattern.CASE_INSENSITIVE);
  private static final Pattern EMAIL_NAME = Pattern.compile("^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+\\z", Pattern.CASE_INSENSITIVE);
  private static final Pattern EMAIL_LABEL = Pattern.compile("^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\\z", Pattern.CASE_INSENSITIVE);

  /** The formats, to replace networknt's own in the 2020-12 dialect. */
  static List<Format> all() {
    return List.of(
        format("date", ReferenceFormats::date),
        format("date-time", ReferenceFormats::dateTime),
        format("email", ReferenceFormats::email),
        format("hostname", value -> HOSTNAME.matcher(value).find()),
        format("uri", value -> NOT_URI_FRAGMENT.matcher(value).find() && URI_PATTERN.matcher(value).find()));
  }

  private interface Check {
    boolean test(String value);
  }

  private static Format format(String name, Check check) {
    return new Format() {
      @Override
      public String getName() {
        return name;
      }

      @Override
      public boolean matches(ExecutionContext context, String value) {
        return check.test(value);
      }
    };
  }

  static boolean date(String value) {
    Matcher m = DATE.matcher(value);
    if (!m.find()) return false;
    int year = Integer.parseInt(m.group(1));
    int month = Integer.parseInt(m.group(2));
    int day = Integer.parseInt(m.group(3));
    boolean leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    return month >= 1 && month <= 12 && day >= 1 && day <= (month == 2 && leap ? 29 : DAYS[month]);
  }

  static boolean time(boolean full, String value) {
    Matcher m = TIME.matcher(value);
    if (!m.find()) return false;
    int hour = Integer.parseInt(m.group(1));
    int minute = Integer.parseInt(m.group(2));
    int second = Integer.parseInt(m.group(3));
    boolean zone = m.group(5) != null && !m.group(5).isEmpty();
    return ((hour <= 23 && minute <= 59 && second <= 59) || (hour == 23 && minute == 59 && second == 60)) && (!full || zone);
  }

  static boolean dateTime(String value) {
    String[] parts = DATE_TIME_SEPARATOR.split(value, -1);
    return parts.length == 2 && date(parts[0]) && time(true, parts[1]);
  }

  static boolean email(String input) {
    if (input.startsWith("\"")) return false;
    String[] parts = input.split("@", -1);
    String name = parts[0];
    String host = parts.length > 1 ? parts[1] : null;
    if (name.isEmpty() || host == null || host.isEmpty() || parts.length != 2 || name.length() > 64 || host.length() > 253) {
      return false;
    }
    if (name.startsWith(".") || name.endsWith(".") || name.contains("..")) return false;
    if (!EMAIL_HOST.matcher(host).find() || !EMAIL_NAME.matcher(name).find()) return false;
    for (String part : host.split("\\.", -1)) {
      if (!EMAIL_LABEL.matcher(part).find()) return false;
    }
    return true;
  }
}
