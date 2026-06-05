import argparse
from views.output import display_domain_overview


def run(params: argparse.Namespace):

    display_domain_overview(params)