#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Расчёт статистики обращений на web - ресурс по логам в формате nginx.
На выходе - html - Таблица с посчитанными данными в разрезе url адресов.

Пример запуска программы:
$ python log_analyzer.py --LOG_DIR .. --LOG_FILE ./log/log.log
Файл-архив логов в папке ..
Файл с логами будет лежать тут: ./log/log.log
На выходе файл .reports/report_results.html
"""
import gzip
import logging
import argparse
import re
from typing import Dict, Tuple, List
import os
import statistics
from itertools import islice


LOGGER = logging.getLogger(__name__)

EXPRESSION = r"""(?P<ipaddress>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) -  - """ + \
  r"""\[((?P<dateandtime>\d{2}\/[a-zA-Z]{3}\/\d{4}:\d{2}:\d{2}:\d{2} (\+|\-)\d{4}))\] """ + \
  r"""((\"(GET|POST) )(?P<url>.+) (HTTP\/1\.1")) (?P<statuscode>\d{3}) (?P<bytessent>\d+) """ + \
  r"""(["](?P<refferer>(\-)|(.+))["]) (["](?P<useragent>.+)["]) (?P<request_time>.+)"""

LINE_NGINX_FULL = re.compile(EXPRESSION, re.IGNORECASE)

config = {
    "REPORT_SIZE": 1000,
    "REPORT_DIR": "./reports",
    "LOG_DIR": "./log"
}

STATISTICS = {
    'count': 0, # сколько раз встречается URL, абсолютное значение
    'count_perc': 0, # сколько раз встречается URL, в процентнах относительно общего числа запросов
    'time_sum': 0, # суммарный $request_time для данного URL'а, абсолютное значение
    'time_perc': 0, # суммарный $request_time для данного URL'а, в процентах относительно общего
                    # $request_time всех запросов
    'time_avg': 0, # средний $request_time для данного URL'а
    'time_max': 0, # максимальный $request_time для данного URL'а
    'time_info': list(), # медиана $request_time для данного URL'а
    'time_med': 0 # медиана $request_time для данного URL'а
}

def find_log(log_dir):
    """ найти максимальный по дате в имени файл с логами """

    LOGGER.info('Поиск всех файлов с логами в директории %s', log_dir)

    file_current = None
    for f in os.listdir(log_dir):
        if re.match(r'nginx-access-ui.log-.*.gz', f):
            file = re.match(r'nginx-access-ui.log-.*.gz', f)[0]

            # лексикографическое сравнение файлов (если даты в верном формате,
            # то сравниться корректно)
            if file_current:
                file_new_ = file.split('\\')[-1]
                file_current_ = file_current.split('\\')[-1]
                if file_new_ > file_current_:
                    file_current = file
            else:
                file_current = file

    if not file_current:
        LOGGER.info('файла для парсинга логов не найдено')
        raise FileNotFoundError

    LOGGER.info('будет использоваться для анализа логов файл %s', file_current)
    return os.path.join(log_dir, file_current)

def update_url_data(data: Dict, url: str, **kwargs) -> Dict:
    """
    Обновить статистики в словаре. Ключи словаря - url
    :param data: словарь с url
    :param url: текущий url
    :param kwargs: параметры статистики
    :return: обновленный словарь
    """

    if url in data:
        data[url]['count'] += 1
        data[url]['time_sum'] += kwargs['request_time']
        data[url]['time_max'] = max(kwargs['request_time'], data[url]['time_max'])
        data[url]['time_info'].append(kwargs['request_time'])
    else:
        data[url] = STATISTICS.copy()
        data[url]['count'] = 1
        data[url]['time_sum'] = kwargs['request_time']
        data[url]['time_max'] = kwargs['request_time']
        data[url]['time_info'] = [kwargs['request_time']]

    return data

def parse_logs(file_to_parse: str, thrashhold=0.5) -> Tuple[Dict, Dict]:
    """
    Парсинг файла с логами по строкам и сбор статистики в словарь
    :param file_to_parse: путь до файла с логами
    :return:
    """

    LOGGER.info('парсинг файла %s..', file_to_parse)

    url_data = dict()
    # парсинг лога
    lines_total_cnt = 0
    lines_cnt = 0
    time_sum = 0

    with gzip.open(file_to_parse, 'r') as file:
        for line in file:
            line_ = line.decode('utf-8')

            try:
                vals = [m.groupdict() for m in LINE_NGINX_FULL.finditer(line_)]

                if vals:
                    params = vals[0]

                    url = params['url']
                    request_time = float(params['request_time']) if 'request_time' in params else 0.

                    lines_cnt += 1
                    time_sum += request_time
                    url_data = update_url_data(url_data, url, request_time=request_time)

            except Exception as _:
                pass
            finally:
                lines_total_cnt += 1

    LOGGER.info('total lines in files: %i', lines_total_cnt)
    LOGGER.info('usable lines in files: %i', lines_cnt)
    LOGGER.info('total request_time: %f', time_sum)

    totals = dict()
    totals['lines_total_cnt'] = lines_total_cnt
    totals['lines_cnt'] = lines_cnt
    totals['time_sum'] = time_sum

    if lines_cnt / lines_total_cnt < thrashhold:
        LOGGER.info('большая часть логов не пропаршена')
        raise ValueError

    return url_data, totals

def calculate_statistics(data: Dict, totals: Dict) -> Dict:
    """ посчитать необходимую статистику """
    for url, _ in data.items():
        data[url]['count_perc'] = 100. * data[url]['count'] / totals['lines_cnt']
        data[url]['time_perc'] = 100. * data[url]['time_sum'] / totals['time_sum']
        data[url]['time_avg'] = statistics.mean(data[url]['time_info'])
        data[url]['time_max'] = max(data[url]['time_info'])
        data[url]['time_med'] = statistics.median(data[url]['time_info'])
    return data

def filter_url_time_sum(data: Dict, report_size: int) -> Dict:
    """ взять топ-н url по значениям time_sum """
    data_sorted = {k: v for k, v in reversed(sorted(data.items(),
                                                    key=lambda item: item[1]['time_sum']))}
    data_topn = dict(islice(data_sorted.items(), report_size))
    return data_topn

def make_html_list(data):
    """ собрать список словарей для html-шаблона """

    LOGGER.info('сбор значений из словаря в список')
    final_result = []
    for url, stat in data.items():
        result = {}
        result["url"] = url
        result["count"] = stat['count']
        result["count_perc"] = stat['count_perc']
        result["time_max"] = stat['time_max']
        result["time_avg"] = stat['time_avg']
        result["time_med"] = stat["time_med"]
        result["time_perc"] = stat['time_perc']
        result["time_sum"] = stat['time_sum']

        final_result.append(result)
    return final_result

def html_insert(html_insertion: List, report_dir: str,
                template_out='report_result.html'):
    """ вставить строку в файл html-шаблон """

    template_in = os.path.join(report_dir, 'report.html')
    template_out = os.path.join(report_dir, template_out)

    LOGGER.info('вставка строки в html-файл')

    fin = open(template_in, "rt")
    fout = open(template_out, "wt")

    for line in fin:
        fout.write(line.replace('$table_json', str(html_insertion)))
    fin.close()
    fout.close()

    LOGGER.info('отчёт создан! файл: %s', template_out)

def main(log_dir, report_dir, report_size):
    """ расчёт статистик из логов nginx """

    file_to_parse = find_log(log_dir)

    url_data, totals = parse_logs(file_to_parse)

    url_data = calculate_statistics(url_data, totals)

    url_data_topn = filter_url_time_sum(url_data, report_size)

    html_list = make_html_list(url_data_topn)

    html_insert(html_list, report_dir)


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='list of parameters')

    parser.add_argument('--REPORT_SIZE',
                        dest='REPORT_SIZE', type=int, required=False,
                        default=None,
                        help='number of url to report')

    parser.add_argument('--LOG_DIR',
                        dest='LOG_DIR', type=str, required=False,
                        default=None,
                        help='path to file to parse')

    parser.add_argument('--REPORT_DIR',
                        dest='REPORT_DIR', type=str, required=False,
                        default=None,
                        help='path to htmp reports')

    parser.add_argument('--LOG_FILE',
                        dest='LOG_FILE', type=str, required=False,
                        default=None,
                        help='logging file name')

    # слияние дефолтного конфига
    config_ = vars(parser.parse_args())

    # обновить конфиги, если не None
    config.update((k, v) for k, v in config_.items() if v is not None)

    # логгер stdout по дефолту
    logging.basicConfig(filename=config_['LOG_FILE'],
                        level=logging.DEBUG,
                        datefmt='%Y.%m.%d %H:%M:%S',
                        format='[%(asctime)s] %(levelname).1s %(message)s',
                        filemode='w')

    if config_['LOG_FILE']:
        print('логгирование в файл %s', config_['LOG_FILE'])
        LOGGER.info('configs: \n %s', str(config))

    try:
        REPORT_FILE = os.path.join(config['REPORT_DIR'], 'report_result.html')
        if os.path.exists(REPORT_FILE):
            LOGGER.info('файл отчёта %s уже существует', REPORT_FILE)
            raise FileExistsError

        main(log_dir=config['LOG_DIR'],
             report_dir=config['REPORT_DIR'],
             report_size=config['REPORT_SIZE'])

    except Exception as _:
        LOGGER.info(_)
        LOGGER.info('программа не выполнена')
