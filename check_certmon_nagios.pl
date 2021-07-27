#!/usr/bin/perl -w

# Nagios plugin that checks status of a k8s-certmon endpoint (https://github.com/olesku/k8s-certmon).
# Author: Ole Fredrik Skudsvik <ole.skudsvik@gmail.com>

# nagios: -epn
use strict;
use LWP::UserAgent();
use JSON::Parse ':all';

my ($url) = @ARGV;
defined $url or die("Usage:\n " . $0 . " <url>\n");

my %handlers = (
  200 => \&h_200,
  201 => \&h_201,
  202 => \&h_202
);

my $ua =  LWP::UserAgent->new(timeout => 10);
my $resp = $ua->get($url);

if ($resp->is_success) {
  if (exists($handlers{$resp->code})) {
    my $json_data = parse_json_safe($resp->content);

    if (!$json_data) {
      printf("CRITICAL: Invalid JSON response from '%s'.\n", $url);
      exit(2);
    }

    $handlers{$resp->code}($json_data);
  } else {
    printf("CRITICAL: Got invalid status code '%s'.\n", $resp->status_line, $url);
    exit(2);
  }
} else {
  printf("CRITICAL: Request to %s failed.\n", $url);
  exit(2);
}

# No certificate errors or warnings found.
sub h_200 {
  printf("OK: All certificates is valid.\n");
  exit(0);
}

# Warnings found.
sub h_201 {
  my $resp = shift;
  my $warnings = join(', ', @{$resp->{'warnings'}});
  printf("WARNING: %s\n", $warnings);
  exit(1);
}

# Critical issues found.
sub h_202 {
  my $resp = shift;
  my $errors = join(', ', @{$resp->{'errors'}});

  printf("Critical: %s\n", $errors);
  exit(2);
}