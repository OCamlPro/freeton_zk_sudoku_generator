(lang dune 2.0)
; This file was generated by drom, using drom.toml
(name sudoku_generator)
(allow_approximate_merlin)
(generate_opam_files false)
(version 0.1.0)
(formatting (enabled_for ocaml reason))

(package
 (name sudoku_generator)
 (synopsis "The sudoku_generator project")
 (description "This is the description\nof the sudoku_generator OCaml project\n")
 (depends
   (ocaml (>= 4.07.0))
   (ez_file ( >= 0.2.0 ))
   ppx_inline_test
   ppx_expect
   odoc
   ocamlformat
  )
 )

