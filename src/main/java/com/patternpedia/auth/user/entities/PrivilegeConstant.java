package com.patternpedia.auth.user.entities;

public interface PrivilegeConstant {
    /** ISSUE */
    String ISSUE_READ                               = "ISSUE_READ";
    String ISSUE_CREATE                             = "ISSUE_CREATE";
    String ISSUE_EDIT                               = "ISSUE_EDIT";
    String ISSUE_DELETE                             = "ISSUE_DELETE";
    String ISSUE_READ_ALL                           = "ISSUE_READ_ALL";
    String ISSUE_EDIT_ALL                           = "ISSUE_EDIT_ALL";
    String ISSUE_DELETE_ALL                         = "ISSUE_DELETE_ALL";
    String ISSUE_TO_PATTERN_CANDIDATE               = "ISSUE_TO_PATTERN_CANDIDATE";
    /** CANDIDATE */
    String PATTERN_CANDIDATE_READ                   = "PATTERN_CANDIDATE_READ";
    String PATTERN_CANDIDATE_CREATE                 = "PATTERN_CANDIDATE_CREATE";
    String PATTERN_CANDIDATE_EDIT                   = "PATTERN_CANDIDATE_EDIT";
    String PATTERN_CANDIDATE_DELETE                 = "PATTERN_CANDIDATE_DELETE";
    String PATTERN_CANDIDATE_READ_ALL               = "PATTERN_CANDIDATE_READ_ALL";
    String PATTERN_CANDIDATE_EDIT_ALL               = "PATTERN_CANDIDATE_EDIT_ALL";
    String PATTERN_CANDIDATE_DELETE_ALL             = "PATTERN_CANDIDATE_DELETE_ALL";
    String PATTERN_CANDIDATE_TO_PATTERN             = "PATTERN_CANDIDATE_TO_PATTERN";
    /** Pattern */
    String APPROVED_PATTERN_READ                    = "APPROVED_PATTERN_READ";
    String APPROVED_PATTERN_CREATE                  = "APPROVED_PATTERN_CREATE";
    String APPROVED_PATTERN_EDIT                    = "APPROVED_PATTERN_EDIT";
    String APPROVED_PATTERN_DELETE                  = "APPROVED_PATTERN_DELETE";
    String APPROVED_PATTERN_READ_ALL                = "APPROVED_PATTERN_READ_ALL";
    String APPROVED_PATTERN_EDIT_ALL                = "APPROVED_PATTERN_EDIT_ALL";
    String APPROVED_PATTERN_DELETE_ALL              = "APPROVED_PATTERN_DELETE_ALL";
    /** USER */
    String USER_READ                                = "USER_READ";
    String USER_CREATE                              = "USER_CREATE";
    String USER_EDIT                                = "USER_EDIT";
    String USER_DELETE                              = "USER_DELETE";
    String USER_READ_ALL                            = "USER_READ_ALL";
    String USER_EDIT_ALL                            = "USER_EDIT_ALL";
    String USER_DELETE_ALL                          = "USER_DELETE_ALL";
    String USER_ALL                                 = "USER_ALL";
    /** GENERAL */
    String COMMENT                                  = "COMMENT";
    String VOTE                                     = "VOTE";
    String EVIDENCE                                 = "EVIDENCE";
}
