#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Тесты для функций из log_analyzer.py

python -m unittest test_log_analyzer
python -m unittest test_log_analyzer.TestFindLog.test_find_log
python -m unittest test_log_analyzer.TestMainFunctions.test_make_html_list
python -m unittest test_log_analyzer.TestMainFunctions.test_html_insert
"""
import os
import unittest
import logging
from log_analyzer import update_url_data, find_log, make_html_list, html_insert, filter_url_time_sum
from log_analyzer import STATISTICS


logging.basicConfig(level=logging.DEBUG,
                    datefmt='%Y.%m.%d %H:%M:%S',
                    format='[%(asctime)s] %(levelname).1s %(message)s')

LOGGER = logging.getLogger(__name__)

class TestFindLog(unittest.TestCase):
    """ Тестирование поиска логов """

    files = ['./log/nginx-access-ui.log-21000101.gz',
             './log/nginx-access-ui.log-21000102.gz',
             './log/nginx-access-ui.log-21000103.gz']

    @classmethod
    def setUp(cls):
        for test_file in cls.files:
            with open(test_file, 'tw', encoding='utf-8') as _:
                pass

    @classmethod
    def tearDown(cls):
        for test_file in cls.files:
            os.remove(test_file)

    def test_find_log(self):
        """ поиск лога в указанной директории """
        file_current = find_log('./log')

        self.assertEqual(file_current, os.path.join('./log', "nginx-access-ui.log-21000103.gz"))

class TestMainFunctions(unittest.TestCase):
    """ тесты для основных функций из log_analyzer """

    def test_update_url_data(self):
        """ тест обновления словаря для url из логов """

        url_data = {"a": STATISTICS.copy(),
                    "b": STATISTICS.copy()}

        url_data = update_url_data(url_data, "b", request_time=2.)
        url_data = update_url_data(url_data, "b", request_time=2.)
        self.assertEqual(url_data["b"]["time_sum"], 4.)

    def test_filter_url_time_sum(self):
        """ фильтрация и сортировка словарей по time_sum """
        data = {"a": STATISTICS.copy(),
                "b": STATISTICS.copy(),
                "c": STATISTICS.copy(),
                }

        data["a"]["time_info"] = [1., 2.]
        data["b"]["time_info"] = [3., 2., 5.]
        data["a"]["time_sum"] = 1.
        data["b"]["time_sum"] = 3.
        data["c"]["time_sum"] = 6.

        res = filter_url_time_sum(data, 2)
        self.assertEqual('a' not in res, True)
        self.assertEqual(len(res.keys()), 2)

    def test_make_html_list(self):
        """ создание списка из словарей для вставки в html """

        data = {"a": STATISTICS.copy(),
                "b": STATISTICS.copy()}
        data["a"]["time_med"] = 1.5
        data["b"]["time_med"] = 3.0

        html_list = make_html_list(data)
        html_list_ = [
            {'url': 'a', 'count': 0, 'count_perc': 0, 'time_max': 0, 'time_avg': 0,
             'time_med': 1.5, 'time_perc': 0, 'time_sum': 0},
            {'url': 'b', 'count': 0, 'count_perc': 0, 'time_max': 0, 'time_avg': 0,
             'time_med': 3.0, 'time_perc': 0, 'time_sum': 0}
        ]
        self.assertListEqual(html_list, html_list_)

    def test_html_insert(self):
        """ тестирование создание отчёта по шаблону """

        report_dir = './reports/'
        template_out = './reports/report_test.html'

        html_insertion = [{'url': 'a', 'count': 0, 'count_perc': 0, 'time_max': 0, 'time_avg': 0,
                           'time_med': 1.5, 'time_perc': 0, 'time_sum': 0},
                          {'url': 'b', 'count': 0, 'count_perc': 0, 'time_max': 0, 'time_avg': 0,
                           'time_med': 3.0, 'time_perc': 0, 'time_sum': 0}]

        html_insert(html_insertion, report_dir, 'report_test.html')
        self.assertEqual(os.path.exists(template_out), True)


if __name__ == '__main__':
    unittest.main()
