import React, { useContext } from 'react'
import notecontext from "../context/notes/noteContext"

const NoteItem = (props) => {
    const context = useContext(notecontext);
    const { deleteNote } = context;
    const { note, updatenote } = props;
    return (
        <div className="col-md-3">

            <div className="card my-3" >

                <div className="card-body">
                    <div className="d-flex align-items-center">
                        <h5 className="card-title">{note.title}</h5>
                        <i className="fa-solid fa-trash-alt mx-2" onClick={() => {
                            deleteNote(note._id);
                            props.showAlert("Sussfully Deleted", "success");
                        }}></i>
                        <i className="fa-regular fa-pen-to-square fa-fw mx-2" onClick={() => { updatenote(note) }}></i>
                    </div>
                    <p className="card-text">{note.description}</p>
                </div>
            </div>
        </div>
    )
}

export default NoteItem
