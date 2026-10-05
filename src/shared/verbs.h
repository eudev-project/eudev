/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* The messages of systemd's dispatch_verb() about a missing or unknown command verb, for a program that
 * takes the verbs in verbs, in the order its messages list them. */

/* "Command verb required (one of help, info, …)." */
void log_verb_required(char * const *verbs);

/* "Unknown command verb 'x', did you mean 'y'?", with the verb that is closest to name, the shortest
 * one that begins with it, or else the first one with the smallest Levenshtein distance to it, if that
 * is at most 5, or "Unknown command verb 'x'." if no verb is close. */
void log_unknown_verb(char * const *verbs, const char *name);
