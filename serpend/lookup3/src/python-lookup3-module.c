#include <Python.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lookup3.h"

static PyObject *
Py_lookup3_hash64(PyObject *self, PyObject *args)
{
	Py_buffer  byte_buffer;
	uint64_t   hash;

	if (!PyArg_ParseTuple(args, "y*", &byte_buffer))
		return NULL;


    hash = hash64(byte_buffer.buf, byte_buffer.len);

    assert(sizeof(unsigned long long) == sizeof(uint64_t));
	return PyLong_FromUnsignedLongLong(hash);
}


static PyMethodDef lookup3_methods[] =
{
	{
	    "hash64",
	    (PyCFunction) Py_lookup3_hash64,
	    METH_VARARGS | METH_KEYWORDS,
	    "Returns a hash based on lookup3 little hash (systemd function)"
	},
	{NULL, NULL, 0, NULL}	 /* sentinel */
};

static struct PyModuleDef lookup3_module =
{
   PyModuleDef_HEAD_INIT,
   "lookup3",   /* name of module */
   "A lookup3 module, making a 64bit hash (as used in systemd)", /* module documentation, may be NULL */
   -1,       /* size of per-interpreter state of the module,
                or -1 if the module keeps state in global variables. */
   lookup3_methods
};

PyMODINIT_FUNC
PyInit_lookup3(void)
{
    return PyModule_Create(&lookup3_module);
}
