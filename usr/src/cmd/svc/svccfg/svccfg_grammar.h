
typedef union
#ifdef __cplusplus
	YYSTYPE
#endif
 {
	int tok;
	char *str;
	uu_list_t *uul;
} YYSTYPE;
extern YYSTYPE yylval;
# define SCC_VALIDATE 257
# define SCC_IMPORT 258
# define SCC_EXPORT 259
# define SCC_ARCHIVE 260
# define SCC_APPLY 261
# define SCC_EXTRACT 262
# define SCC_CLEANUP 263
# define SCC_REPOSITORY 264
# define SCC_INVENTORY 265
# define SCC_SET 266
# define SCC_END 267
# define SCC_HELP 268
# define SCC_RESTORE 269
# define SCC_LIST 270
# define SCC_ADD 271
# define SCC_DELETE 272
# define SCC_SELECT 273
# define SCC_UNSELECT 274
# define SCC_LISTPG 275
# define SCC_ADDPG 276
# define SCC_DELPG 277
# define SCC_DELHASH 278
# define SCC_LISTPROP 279
# define SCC_SETPROP 280
# define SCC_DELPROP 281
# define SCC_EDITPROP 282
# define SCC_DESCRIBE 283
# define SCC_ADDPROPVALUE 284
# define SCC_DELPROPVALUE 285
# define SCC_SETENV 286
# define SCC_UNSETENV 287
# define SCC_LISTSNAP 288
# define SCC_SELECTSNAP 289
# define SCC_REVERT 290
# define SCC_REFRESH 291
# define SCS_REDIRECT 292
# define SCS_NEWLINE 293
# define SCS_EQUALS 294
# define SCS_LPAREN 295
# define SCS_RPAREN 296
# define SCV_WORD 297
# define SCV_STRING 298
# define SCC_DELNOTIFY 299
# define SCC_SETNOTIFY 300
# define SCC_LISTNOTIFY 301
